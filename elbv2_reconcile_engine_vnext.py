#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Set

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


# =============================================================================
# CONSTANTS
# =============================================================================

DEFAULT_REPORT_DIR = "elbv2_reports"
DEFAULT_ROLLBACK_DIR = "elbv2_rollback"

BOTO_CONFIG = Config(
    retries={
        "mode": "adaptive",
        "max_attempts": 10,
    }
)

TG_SUPPORTED_ATTR_KEYS = [
    "deregistration_delay.timeout_seconds",
    "stickiness.enabled",
    "stickiness.type",
    "stickiness.lb_cookie.duration_seconds",
    "slow_start.duration_seconds",
    "load_balancing.algorithm.type",
    "load_balancing.cross_zone.enabled",
    "target_group_health.dns_failover.minimum_healthy_targets.count",
    "target_group_health.dns_failover.minimum_healthy_targets.percentage",
    "target_group_health.unhealthy_state_routing.minimum_healthy_targets.count",
    "target_group_health.unhealthy_state_routing.minimum_healthy_targets.percentage",
]

LB_SUPPORTED_ATTR_KEYS = [
    # REMOVE these three lines for cold DR:
    # "access_logs.s3.enabled",
    # "access_logs.s3.bucket",
    # "access_logs.s3.prefix",

    "deletion_protection.enabled",
    "idle_timeout.timeout_seconds",
    "routing.http.desync_mitigation_mode",
    "routing.http.drop_invalid_header_fields.enabled",
    "routing.http.preserve_host_header.enabled",
    "routing.http.x_amzn_tls_version_and_cipher_suite.enabled",
    "routing.http.xff_client_port.enabled",
    "routing.http.xff_header_processing.mode",
    "routing.http2.enabled",
    "waf.fail_open.enabled",
    "load_balancing.cross_zone.enabled",
    "dns_record.client_routing_policy",
]

TG_IMMUTABLE_FIELDS = [
    "Protocol",
    "Port",
    "TargetType",
    "IpAddressType",
    "ProtocolVersion",
]

TG_MUTABLE_FIELDS = [
    "HealthCheckProtocol",
    "HealthCheckPort",
    "HealthCheckEnabled",
    "HealthCheckPath",
    "HealthCheckIntervalSeconds",
    "HealthCheckTimeoutSeconds",
    "HealthyThresholdCount",
    "UnhealthyThresholdCount",
    "Matcher",
]

TG_INTEGER_MUTABLE_FIELDS = {
    "HealthCheckIntervalSeconds",
    "HealthCheckTimeoutSeconds",
    "HealthyThresholdCount",
    "UnhealthyThresholdCount",
}

LB_IMMUTABLE_FIELDS = [
    "Type",
    "Scheme",
    "IpAddressType",
]

SYSTEM_TAG_PREFIXES = (
    "aws:",
    "elasticbeanstalk:",
    "kubernetes.io/",
    "eks:",
    "aws:cloudformation:",
    "aws:autoscaling:",
)

# If non-empty, only these keys are considered "important true tags".
ALLOWED_TAG_KEYS: Set[str] = {
    "Name",
    "Environment",
    "Owner",
    "CostCenter",
    "Application",
}


# =============================================================================
# LOGGING / FILE UTILS
# =============================================================================

def log(msg: str) -> None:
    print(msg, flush=True)


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def ensure_dir(path: str) -> None:
    if path:
        os.makedirs(path, exist_ok=True)


def read_json(path: str) -> Any:
    abs_path = os.path.abspath(os.path.join(os.getcwd(), path))
    with open(abs_path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str, data: Any) -> None:
    parent = os.path.dirname(path)
    if parent:
        ensure_dir(parent)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


# =============================================================================
# NORMALIZATION
# =============================================================================

def normalize_text(value: Optional[str]) -> str:
    if not value:
        return ""
    value = value.strip().lower()
    value = value.replace("\u2011", "-").replace("\u2013", "-").replace("\u2014", "-")
    value = re.sub(r"[^a-z0-9.*]+", "-", value)
    value = re.sub(r"-+", "-", value)
    return value.strip("-")


def normalize_name_for_match(name: Optional[str]) -> str:
    if not name:
        return ""

    value = normalize_text(name)
    tokens = [
        t for t in value.split("-")
        if t not in {
            "prod", "production", "prd",
            "dr", "disaster", "recovery",
            "dev", "qa", "uat", "test", "stage", "staging",
            "blue", "green",
        }
    ]

    value = "-".join(tokens)
    value = re.sub(r"^[a-z]-[a-z0-9]{6,16}-", "", value)
    value = re.sub(r"-(?:[a-f0-9]{6,16}|[a-z0-9]{8,16})$", "", value)
    value = re.sub(r"-+", "-", value)
    return value.strip("-")


def normalize_domain(domain: Optional[str]) -> str:
    if not domain:
        return ""
    domain = domain.strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    return domain


def clean_tags(tags: List[Dict[str, str]]) -> List[Dict[str, str]]:
    cleaned: List[Dict[str, str]] = []
    seen = set()

    for tag in tags or []:
        key = tag.get("Key")
        value = tag.get("Value", "")

        if not key:
            continue
        if key.startswith(SYSTEM_TAG_PREFIXES):
            continue
        if ALLOWED_TAG_KEYS and key not in ALLOWED_TAG_KEYS:
            continue
        if key in seen:
            continue

        seen.add(key)
        cleaned.append({"Key": key, "Value": value})

    return cleaned


def tag_dict(tags: List[Dict[str, str]]) -> Dict[str, str]:
    return {t["Key"]: t.get("Value", "") for t in clean_tags(tags or []) if t.get("Key")}


def normalize_matcher(matcher: Optional[Dict[str, Any]]) -> Dict[str, str]:
    if not matcher:
        return {}

    out: Dict[str, str] = {}

    if matcher.get("HttpCode") is not None:
        out["HttpCode"] = str(matcher["HttpCode"]).replace(" ", "")

    if matcher.get("GrpcCode") is not None:
        out["GrpcCode"] = str(matcher["GrpcCode"]).replace(" ", "")

    return out


def normalize_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: normalize_value(v) for k, v in sorted(value.items()) if v is not None and v != {}}
    if isinstance(value, list):
        return [normalize_value(v) for v in value]
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if value is None:
        return None
    return str(value)


# =============================================================================
# MODELS
# =============================================================================

@dataclass
class Environment:
    profile: Optional[str]
    region: str
    vpc_id: str
    account_id: Optional[str] = None
    role_arn: Optional[str] = None


@dataclass
class Policy:
    register_targets: bool = False
    create_missing_load_balancers: bool = False
    create_missing_target_groups: bool = True
    sync_load_balancer_attributes: bool = True
    sync_target_group_attributes: bool = True
    sync_target_group_settings: bool = True
    sync_listener_rules: bool = True
    sync_listeners: bool = True
    sync_tags: bool = True
    allow_extra_target_rules: bool = True
    skip_target_registration: bool = True
    allow_certificate_domain_match: bool = True
    auto_map_subnets: bool = False
    auto_map_security_groups: bool = False
    # For cross-region DR where AZ IDs cannot match, map source/target subnets by
    # deterministic AZ ordinal within each VPC after route/profile filtering.
    # This avoids hardcoding subnet IDs while still failing closed on close ties.
    cross_region_az_ordinal_mapping: bool = True


@dataclass
class MappingConfig:
    subnets: Dict[str, str] = field(default_factory=dict)
    security_groups: Dict[str, str] = field(default_factory=dict)
    certificates: Dict[str, str] = field(default_factory=dict)
    load_balancers: Dict[str, str] = field(default_factory=dict)
    target_groups: Dict[str, str] = field(default_factory=dict)


@dataclass
class ConfigFile:
    source: Environment
    target: Environment
    mappings: MappingConfig = field(default_factory=MappingConfig)
    policy: Policy = field(default_factory=Policy)


@dataclass
class Args:
    info_file: str
    dry_run: bool
    report_only: bool
    yes: bool
    allow_legacy: bool
    no_create_missing_tg: bool
    no_create_missing_lb: bool
    no_sync_tags: bool
    no_sync_listener_rules: bool
    skip_target_registration: bool
    report_path: str
    report_dir: str
    rollback_dir: str
    debug_discovery: bool = False


@dataclass
class CertificateState:
    arn: str
    domain_name: str
    sans: List[str] = field(default_factory=list)
    status: str = ""
    not_after: Optional[str] = None

    @property
    def domains(self) -> Set[str]:
        values = {normalize_domain(self.domain_name)}
        values.update(normalize_domain(x) for x in self.sans)
        return {x for x in values if x}


@dataclass
class TargetGroupState:
    name: str
    arn: Optional[str]
    vpc_id: Optional[str]
    fields: Dict[str, Any]
    attributes: Dict[str, str]
    tags: Dict[str, str]
    load_balancer_arns: List[str] = field(default_factory=list)
    target_health_count: int = 0


@dataclass
class LoadBalancerState:
    name: str
    arn: str
    dns_name: str
    fields: Dict[str, Any]
    attributes: Dict[str, str]
    tags: Dict[str, str]
    security_groups: List[str] = field(default_factory=list)
    subnet_ids: List[str] = field(default_factory=list)


@dataclass
class ListenerState:
    arn: str
    load_balancer_arn: str
    port: int
    protocol: str
    ssl_policy: Optional[str]
    certificates: List[str]
    default_actions: List[Dict[str, Any]]


@dataclass
class ListenerRuleState:
    arn: str
    listener_arn: str
    priority: str
    conditions: List[Dict[str, Any]]
    actions: List[Dict[str, Any]]
    is_default: bool = False


@dataclass
class FieldDrift:
    field: str
    source_value: Any
    target_value: Any


@dataclass
class ResourceAudit:
    resource_type: str
    name: str
    source_arn: Optional[str] = None
    target_arn: Optional[str] = None
    exists: bool = False
    in_sync: bool = False
    action: str = "SKIP"
    drift: List[FieldDrift] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class TargetGroupAudit:
    name: str
    source_arn: Optional[str] = None
    target_arn: Optional[str] = None
    exists: bool = False
    immutable_match: bool = True
    mutable_match: bool = True
    attribute_match: bool = True
    tag_match: bool = True
    association_match: bool = True
    target_registration_status: str = "SKIPPED"
    immutable_drift: List[FieldDrift] = field(default_factory=list)
    mutable_drift: List[FieldDrift] = field(default_factory=list)
    attribute_drift: List[FieldDrift] = field(default_factory=list)
    tag_drift: List[FieldDrift] = field(default_factory=list)
    association_notes: List[str] = field(default_factory=list)
    action: str = "SKIP"
    notes: List[str] = field(default_factory=list)

    @property
    def in_sync(self) -> bool:
        return (
            self.exists
            and self.immutable_match
            and self.mutable_match
            and self.attribute_match
            and self.tag_match
            and self.association_match
        )

    @property
    def requires_create(self) -> bool:
        return not self.exists

    @property
    def requires_update(self) -> bool:
        return self.exists and (bool(self.mutable_drift) or bool(self.attribute_drift) or bool(self.tag_drift))


@dataclass
class WorldState:
    target_groups: Dict[str, TargetGroupState]
    target_groups_by_arn: Dict[str, TargetGroupState]
    load_balancers: Dict[str, LoadBalancerState]
    load_balancers_by_arn: Dict[str, LoadBalancerState]
    listeners: Dict[str, ListenerState]
    listener_rules: Dict[str, List[ListenerRuleState]]
    certificates: Dict[str, CertificateState]


@dataclass
class MatchContext:
    tg_source_to_target_arn: Dict[str, str] = field(default_factory=dict)
    tg_source_name_to_target_name: Dict[str, str] = field(default_factory=dict)
    lb_source_to_target_arn: Dict[str, str] = field(default_factory=dict)
    lb_source_name_to_target_name: Dict[str, str] = field(default_factory=dict)
    cert_source_to_target_arn: Dict[str, str] = field(default_factory=dict)
    ambiguous: List[Dict[str, Any]] = field(default_factory=list)
    unmatched: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ExecutionContext:
    created_target_groups: List[str] = field(default_factory=list)
    created_load_balancers: List[str] = field(default_factory=list)
    created_listeners: List[str] = field(default_factory=list)
    created_listener_rules: List[str] = field(default_factory=list)
    updated_target_groups: List[str] = field(default_factory=list)
    updated_load_balancers: List[str] = field(default_factory=list)
    updated_listeners: List[str] = field(default_factory=list)
    updated_listener_rules: List[str] = field(default_factory=list)
    failed_actions: List[Dict[str, Any]] = field(default_factory=list)
    rollback_actions: List[Dict[str, Any]] = field(default_factory=list)


# =============================================================================
# CONFIG / CLIENTS
# =============================================================================

def load_config(path: str) -> ConfigFile:
    data = read_json(path)

    if "source" not in data or "target" not in data:
        raise ValueError("Info file must include top-level 'source' and 'target' objects.")

    policy_data = data.get("policy", {}) or {}
    mappings_data = data.get("mappings", {}) or {}
    allowed_mapping_keys = {"subnets", "security_groups", "certificates", "load_balancers", "target_groups"}
    mappings_data = {k: v for k, v in mappings_data.items() if k in allowed_mapping_keys}

    return ConfigFile(
        source=Environment(**data["source"]),
        target=Environment(**data["target"]),
        mappings=MappingConfig(**mappings_data),
        policy=Policy(**policy_data),
    )


def build_session(env: Environment) -> boto3.Session:
    if env.profile:
        base = boto3.Session(profile_name=env.profile, region_name=env.region)
    else:
        base = boto3.Session(region_name=env.region)

    if not env.role_arn:
        return base

    sts = base.client("sts", config=BOTO_CONFIG)
    resp = sts.assume_role(RoleArn=env.role_arn, RoleSessionName=f"elbv2-reconcile-{now_stamp()}")
    creds = resp["Credentials"]

    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=env.region,
    )


def get_elbv2(env: Environment) -> Any:
    return build_session(env).client("elbv2", config=BOTO_CONFIG)


def get_acm(env: Environment) -> Any:
    return build_session(env).client("acm", config=BOTO_CONFIG)


def get_ec2(env: Environment) -> Any:
    return build_session(env).client("ec2", config=BOTO_CONFIG)


# =============================================================================
# AWS DISCOVERY HELPERS
# =============================================================================

def describe_tags(elbv2: Any, arns: List[str]) -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {}
    if not arns:
        return out

    for i in range(0, len(arns), 20):
        chunk = arns[i:i + 20]
        try:
            resp = elbv2.describe_tags(ResourceArns=chunk)
            for desc in resp.get("TagDescriptions", []):
                out[desc["ResourceArn"]] = tag_dict(desc.get("Tags", []))
        except ClientError as exc:
            eprint(f"[WARN] Could not describe tags for {len(chunk)} resource(s): {exc}")
    return out


def describe_load_balancers_by_vpc(elbv2: Any, vpc_id: str) -> List[Dict[str, Any]]:
    paginator = elbv2.get_paginator("describe_load_balancers")
    out: List[Dict[str, Any]] = []

    for page in paginator.paginate(PageSize=400):
        for lb in page.get("LoadBalancers", []):
            if lb.get("VpcId") == vpc_id:
                out.append(lb)

    return out


def describe_lb_attributes(elbv2: Any, lb_arn: str) -> Dict[str, str]:
    try:
        resp = elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
        return {
            item["Key"]: item.get("Value", "")
            for item in resp.get("Attributes", [])
            if item.get("Key") in LB_SUPPORTED_ATTR_KEYS
        }
    except ClientError as exc:
        eprint(f"[WARN] Could not read LB attributes for {lb_arn}: {exc}")
        return {}


def describe_target_groups_by_vpc(elbv2: Any, vpc_id: str) -> List[Dict[str, Any]]:
    paginator = elbv2.get_paginator("describe_target_groups")
    out: List[Dict[str, Any]] = []

    for page in paginator.paginate(PageSize=400):
        for tg in page.get("TargetGroups", []):
            if tg.get("VpcId") == vpc_id:
                out.append(tg)

    return out


def describe_target_group_attributes(elbv2: Any, tg_arn: str) -> Dict[str, str]:
    try:
        resp = elbv2.describe_target_group_attributes(TargetGroupArn=tg_arn)
        return {
            item["Key"]: item.get("Value", "")
            for item in resp.get("Attributes", [])
            if item.get("Key") in TG_SUPPORTED_ATTR_KEYS
        }
    except ClientError as exc:
        eprint(f"[WARN] Could not read TG attributes for {tg_arn}: {exc}")
        return {}


def describe_target_health_count(elbv2: Any, tg_arn: str) -> int:
    try:
        resp = elbv2.describe_target_health(TargetGroupArn=tg_arn)
        return len(resp.get("TargetHealthDescriptions", []))
    except ClientError:
        return 0


def describe_listeners_for_lb(elbv2: Any, lb_arn: str) -> List[Dict[str, Any]]:
    paginator = elbv2.get_paginator("describe_listeners")
    out: List[Dict[str, Any]] = []
    try:
        for page in paginator.paginate(LoadBalancerArn=lb_arn, PageSize=400):
            out.extend(page.get("Listeners", []))
    except ClientError as exc:
        eprint(f"[WARN] Could not describe listeners for {lb_arn}: {exc}")
    return out


def describe_rules_for_listener(elbv2: Any, listener_arn: str) -> List[Dict[str, Any]]:
    paginator = elbv2.get_paginator("describe_rules")
    out: List[Dict[str, Any]] = []
    try:
        for page in paginator.paginate(ListenerArn=listener_arn, PageSize=400):
            out.extend(page.get("Rules", []))
    except ClientError as exc:
        eprint(f"[WARN] Could not describe listener rules for {listener_arn}: {exc}")
    return out


def discover_certificates(env: Environment) -> Dict[str, CertificateState]:
    acm = get_acm(env)
    result: Dict[str, CertificateState] = {}

    paginator = acm.get_paginator("list_certificates")
    statuses = ["ISSUED", "PENDING_VALIDATION", "EXPIRED", "INACTIVE"]
    cert_arns: List[str] = []

    for page in paginator.paginate(CertificateStatuses=statuses):
        for item in page.get("CertificateSummaryList", []):
            arn = item.get("CertificateArn")
            if arn:
                cert_arns.append(arn)

    for arn in cert_arns:
        try:
            resp = acm.describe_certificate(CertificateArn=arn)
            cert = resp.get("Certificate", {})
            state = CertificateState(
                arn=arn,
                domain_name=cert.get("DomainName", ""),
                sans=cert.get("SubjectAlternativeNames", []) or [],
                status=cert.get("Status", ""),
                not_after=str(cert.get("NotAfter")) if cert.get("NotAfter") else None,
            )
            result[arn] = state
        except ClientError as exc:
            eprint(f"[WARN] Could not describe ACM cert {arn}: {exc}")

    return result


# =============================================================================
# STATE NORMALIZATION
# =============================================================================

def normalize_target_group(tg: Dict[str, Any], attrs: Dict[str, str], tags: Dict[str, str], health_count: int) -> TargetGroupState:
    fields = {
        "TargetGroupName": tg.get("TargetGroupName"),
        "Protocol": tg.get("Protocol"),
        "Port": tg.get("Port"),
        "TargetType": tg.get("TargetType"),
        "IpAddressType": tg.get("IpAddressType"),
        "ProtocolVersion": tg.get("ProtocolVersion"),
        "HealthCheckProtocol": tg.get("HealthCheckProtocol"),
        "HealthCheckPort": tg.get("HealthCheckPort"),
        "HealthCheckEnabled": tg.get("HealthCheckEnabled"),
        "HealthCheckPath": tg.get("HealthCheckPath"),
        "HealthCheckIntervalSeconds": tg.get("HealthCheckIntervalSeconds"),
        "HealthCheckTimeoutSeconds": tg.get("HealthCheckTimeoutSeconds"),
        "HealthyThresholdCount": tg.get("HealthyThresholdCount"),
        "UnhealthyThresholdCount": tg.get("UnhealthyThresholdCount"),
        "Matcher": normalize_matcher(tg.get("Matcher")),
    }
    fields = {k: normalize_value(v) for k, v in fields.items() if v is not None and v != {}}
    name = tg.get("TargetGroupName")
    if not name:
        raise ValueError(f"Target group missing TargetGroupName: {tg}")

    return TargetGroupState(
        name=name,
        arn=tg.get("TargetGroupArn"),
        vpc_id=tg.get("VpcId"),
        fields=fields,
        attributes={k: str(v) for k, v in sorted((attrs or {}).items())},
        tags={k: str(v) for k, v in sorted((tags or {}).items())},
        load_balancer_arns=sorted(tg.get("LoadBalancerArns", []) or []),
        target_health_count=health_count,
    )


def normalize_load_balancer(lb: Dict[str, Any], attrs: Dict[str, str], tags: Dict[str, str]) -> LoadBalancerState:
    name = lb.get("LoadBalancerName")
    arn = lb.get("LoadBalancerArn")
    if not name or not arn:
        raise ValueError(f"Load balancer missing name/arn: {lb}")

    azs = lb.get("AvailabilityZones", []) or []
    subnet_ids = sorted([az.get("SubnetId") for az in azs if az.get("SubnetId")])

    fields = {
        "LoadBalancerName": name,
        "Type": lb.get("Type"),
        "Scheme": lb.get("Scheme"),
        "IpAddressType": lb.get("IpAddressType"),
        "VpcId": lb.get("VpcId"),
    }
    fields = {k: normalize_value(v) for k, v in fields.items() if v is not None and v != {}}

    return LoadBalancerState(
        name=name,
        arn=arn,
        dns_name=lb.get("DNSName", ""),
        fields=fields,
        attributes={k: str(v) for k, v in sorted((attrs or {}).items())},
        tags={k: str(v) for k, v in sorted((tags or {}).items())},
        security_groups=sorted(lb.get("SecurityGroups", []) or []),
        subnet_ids=subnet_ids,
    )


def strip_aws_generated_keys(obj: Any) -> Any:
    if isinstance(obj, dict):
        ignored = {
            "TargetGroupArn",
            "RuleArn",
            "ListenerArn",
            "LoadBalancerArn",
            "Order",
        }
        return {
            k: strip_aws_generated_keys(v)
            for k, v in sorted(obj.items())
            if k not in ignored and v is not None and v != [] and v != {}
        }
    if isinstance(obj, list):
        return [strip_aws_generated_keys(v) for v in obj]
    return normalize_value(obj)


def canonicalize_conditions(conditions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    clean = [strip_aws_generated_keys(c) for c in conditions or []]
    return sorted(clean, key=lambda x: json.dumps(x, sort_keys=True))


def _is_effectively_false(value: Any) -> bool:
    """Return True for AWS/API/config representations of disabled booleans."""
    if value is False:
        return True
    if isinstance(value, str) and value.strip().lower() in {"false", "0", "no"}:
        return True
    return False


def _normalize_disabled_stickiness_in_action(action: Any) -> Any:
    """Remove non-semantic stickiness fields when stickiness is disabled.

    AWS can return TargetGroupStickinessConfig with only Enabled=False in one
    environment and Enabled=False plus DurationSeconds=3600 in another. When
    stickiness is disabled, DurationSeconds has no effective routing behavior,
    so treating it as drift creates noisy listener default-action updates.

    This function is intentionally recursive because AWS may surface the
    TargetGroupStickinessConfig under listener default actions or listener rule
    actions, and values may already have passed through normalize_value().
    """
    if isinstance(action, dict):
        out = {k: _normalize_disabled_stickiness_in_action(v) for k, v in action.items()}

        sticky = out.get("TargetGroupStickinessConfig")
        if isinstance(sticky, dict) and _is_effectively_false(sticky.get("Enabled")):
            sticky.pop("DurationSeconds", None)

        fwd = out.get("ForwardConfig")
        if isinstance(fwd, dict):
            sticky = fwd.get("TargetGroupStickinessConfig")
            if isinstance(sticky, dict) and _is_effectively_false(sticky.get("Enabled")):
                sticky.pop("DurationSeconds", None)

        return out
    if isinstance(action, list):
        return [_normalize_disabled_stickiness_in_action(v) for v in action]
    return action


def canonicalize_actions(actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    clean = [
        _normalize_disabled_stickiness_in_action(strip_aws_generated_keys(a))
        for a in actions or []
    ]
    return sorted(clean, key=lambda x: json.dumps(x, sort_keys=True))


def normalize_listener(listener: Dict[str, Any]) -> Optional[ListenerState]:
    arn = listener.get("ListenerArn")
    lb_arn = listener.get("LoadBalancerArn")
    if not arn or not lb_arn:
        eprint(f"[WARN] Skipping listener with missing ARN or LoadBalancerArn: {listener}")
        return None

    certs = [c.get("CertificateArn") for c in listener.get("Certificates", []) if c.get("CertificateArn")]
    return ListenerState(
        arn=arn,
        load_balancer_arn=lb_arn,
        port=int(listener.get("Port", 0)),
        protocol=listener.get("Protocol", ""),
        ssl_policy=listener.get("SslPolicy"),
        certificates=sorted(certs),
        default_actions=canonicalize_actions(listener.get("DefaultActions", [])),
    )


def normalize_listener_rule(rule: Dict[str, Any], listener_arn_override: Optional[str] = None) -> Optional[ListenerRuleState]:
    arn = rule.get("RuleArn")
    listener_arn = rule.get("ListenerArn") or listener_arn_override
    if not arn or not listener_arn:
        eprint(f"[WARN] Skipping rule with missing ARN or ListenerArn: {rule}")
        return None

    priority = str(rule.get("Priority", ""))
    return ListenerRuleState(
        arn=arn,
        listener_arn=listener_arn,
        priority=priority,
        conditions=canonicalize_conditions(rule.get("Conditions", [])),
        actions=canonicalize_actions(rule.get("Actions", [])),
        is_default=(priority == "default"),
    )


def discover_world(env: Environment) -> WorldState:
    elbv2 = get_elbv2(env)

    raw_lbs = describe_load_balancers_by_vpc(elbv2, env.vpc_id)
    lb_arns = [lb["LoadBalancerArn"] for lb in raw_lbs if lb.get("LoadBalancerArn")]
    lb_tags_by_arn = describe_tags(elbv2, lb_arns)

    lbs: Dict[str, LoadBalancerState] = {}
    lbs_by_arn: Dict[str, LoadBalancerState] = {}
    listeners: Dict[str, ListenerState] = {}
    listener_rules: Dict[str, List[ListenerRuleState]] = {}

    for lb in raw_lbs:
        lb_arn = lb.get("LoadBalancerArn")
        attrs = describe_lb_attributes(elbv2, lb_arn) if lb_arn else {}
        state = normalize_load_balancer(lb, attrs, lb_tags_by_arn.get(lb_arn, {}))
        lbs[state.name] = state
        lbs_by_arn[state.arn] = state

        for listener in describe_listeners_for_lb(elbv2, state.arn):
            ls = normalize_listener(listener)
            if not ls:
                continue
            listeners[ls.arn] = ls
            rules: List[ListenerRuleState] = []
            for r in describe_rules_for_listener(elbv2, ls.arn):
                nr = normalize_listener_rule(r, ls.arn)
                if nr:
                    rules.append(nr)
            listener_rules[ls.arn] = rules

    raw_tgs = describe_target_groups_by_vpc(elbv2, env.vpc_id)
    tg_arns = [tg["TargetGroupArn"] for tg in raw_tgs if tg.get("TargetGroupArn")]
    tg_tags_by_arn = describe_tags(elbv2, tg_arns)

    tgs: Dict[str, TargetGroupState] = {}
    tgs_by_arn: Dict[str, TargetGroupState] = {}

    for tg in raw_tgs:
        arn = tg.get("TargetGroupArn")
        if not arn:
            continue
        attrs = describe_target_group_attributes(elbv2, arn)
        health_count = describe_target_health_count(elbv2, arn)
        state = normalize_target_group(tg, attrs, tg_tags_by_arn.get(arn, {}), health_count)
        tgs[state.name] = state
        tgs_by_arn[state.arn] = state

    certs = discover_certificates(env)

    return WorldState(
        target_groups=tgs,
        target_groups_by_arn=tgs_by_arn,
        load_balancers=lbs,
        load_balancers_by_arn=lbs_by_arn,
        listeners=listeners,
        listener_rules=listener_rules,
        certificates=certs,
    )


# =============================================================================
# DIFF
# =============================================================================

def diff_fields(source: Dict[str, Any], target: Dict[str, Any], fields: List[str]) -> List[FieldDrift]:
    drifts: List[FieldDrift] = []
    for field_name in fields:
        src = normalize_value(source.get(field_name))
        tgt = normalize_value(target.get(field_name))
        if src != tgt:
            drifts.append(FieldDrift(field=field_name, source_value=src, target_value=tgt))
    return drifts


def diff_dict(source: Dict[str, str], target: Dict[str, str], keys: Optional[List[str]] = None) -> List[FieldDrift]:
    compare_keys = sorted(set(keys)) if keys is not None else sorted(set(source.keys()) | set(target.keys()))
    drifts: List[FieldDrift] = []

    for key in compare_keys:
        src = source.get(key)
        tgt = target.get(key)
        if src != tgt:
            drifts.append(FieldDrift(field=key, source_value=src, target_value=tgt))

    return drifts


def diff_source_required_dict(source: Dict[str, str], target: Dict[str, str]) -> List[FieldDrift]:
    drifts: List[FieldDrift] = []
    for key in sorted(source.keys()):
        src = source.get(key)
        tgt = target.get(key)
        if src != tgt:
            drifts.append(FieldDrift(field=key, source_value=src, target_value=tgt))
    return drifts


# =============================================================================
# MATCHING
# =============================================================================

def build_normalized_index(names: List[str]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for name in names:
        out.setdefault(normalize_name_for_match(name), []).append(name)
    return out


def match_by_name(
    source_name: str,
    target_objects: Dict[str, Any],
    normalized_index: Dict[str, List[str]],
    allow_legacy: bool,
    match_context: MatchContext,
    resource_type: str,
) -> Optional[str]:
    if source_name in target_objects:
        return source_name

    if not allow_legacy:
        return None

    normalized = normalize_name_for_match(source_name)
    candidates = normalized_index.get(normalized, [])

    if len(candidates) == 1:
        return candidates[0]

    if len(candidates) > 1:
        match_context.ambiguous.append({
            "resource_type": resource_type,
            "source": source_name,
            "normalized": normalized,
            "candidates": candidates,
        })

    return None


def build_cert_match_map(
    source_certs: Dict[str, CertificateState],
    target_certs: Dict[str, CertificateState],
    allow_domain_match: bool,
) -> Dict[str, str]:
    if not allow_domain_match:
        return {}

    target_domain_index: Dict[str, List[CertificateState]] = {}

    for cert in target_certs.values():
        if cert.status != "ISSUED":
            continue
        for domain in cert.domains:
            target_domain_index.setdefault(domain, []).append(cert)

    out: Dict[str, str] = {}

    for src_arn, src_cert in source_certs.items():
        candidates: List[CertificateState] = []
        for domain in src_cert.domains:
            candidates.extend(target_domain_index.get(domain, []))

        unique = {c.arn: c for c in candidates}
        if not unique:
            continue

        selected = sorted(
            unique.values(),
            key=lambda c: c.not_after or "",
            reverse=True,
        )[0]
        out[src_arn] = selected.arn

    return out


def build_match_context(
    source: WorldState,
    target: WorldState,
    allow_legacy: bool,
    policy: Policy,
    mappings: Optional[MappingConfig] = None,
) -> MatchContext:
    ctx = MatchContext()

    target_tg_norm = build_normalized_index(list(target.target_groups.keys()))
    for src_name, src_tg in sorted(source.target_groups.items()):
        tgt_name = match_by_name(src_name, target.target_groups, target_tg_norm, allow_legacy, ctx, "target_group")
        if tgt_name:
            tgt_tg = target.target_groups[tgt_name]
            if src_tg.arn and tgt_tg.arn:
                ctx.tg_source_to_target_arn[src_tg.arn] = tgt_tg.arn
                ctx.tg_source_name_to_target_name[src_name] = tgt_name
        else:
            ctx.unmatched.append({"resource_type": "target_group", "source": src_name})

    target_lb_norm = build_normalized_index(list(target.load_balancers.keys()))
    for src_name, src_lb in sorted(source.load_balancers.items()):
        tgt_name = match_by_name(src_name, target.load_balancers, target_lb_norm, allow_legacy, ctx, "load_balancer")
        if tgt_name:
            tgt_lb = target.load_balancers[tgt_name]
            ctx.lb_source_to_target_arn[src_lb.arn] = tgt_lb.arn
            ctx.lb_source_name_to_target_name[src_name] = tgt_name
        else:
            ctx.unmatched.append({"resource_type": "load_balancer", "source": src_name})

    ctx.cert_source_to_target_arn = build_cert_match_map(
        source.certificates,
        target.certificates,
        allow_domain_match=policy.allow_certificate_domain_match,
    )

    if mappings:
        # Explicit mappings always win over inferred mappings.
        for src_name, tgt_name in mappings.target_groups.items():
            src_tg = source.target_groups.get(src_name)
            tgt_tg = target.target_groups.get(tgt_name)
            if src_tg and tgt_tg and src_tg.arn and tgt_tg.arn:
                ctx.tg_source_to_target_arn[src_tg.arn] = tgt_tg.arn
                ctx.tg_source_name_to_target_name[src_name] = tgt_name

        for src_name, tgt_name in mappings.load_balancers.items():
            src_lb = source.load_balancers.get(src_name)
            tgt_lb = target.load_balancers.get(tgt_name)
            if src_lb and tgt_lb:
                ctx.lb_source_to_target_arn[src_lb.arn] = tgt_lb.arn
                ctx.lb_source_name_to_target_name[src_name] = tgt_name

        for src_cert, tgt_cert in mappings.certificates.items():
            # Allow either ARN-to-ARN or domain-to-ARN mapping.
            if src_cert.startswith("arn:aws:acm:"):
                ctx.cert_source_to_target_arn[src_cert] = tgt_cert
                continue
            wanted = normalize_domain(src_cert)
            for cert in source.certificates.values():
                if wanted in cert.domains:
                    ctx.cert_source_to_target_arn[cert.arn] = tgt_cert

    return ctx

# =============================================================================
# REMAPPING
# =============================================================================

def remap_actions(actions: List[Dict[str, Any]], ctx: MatchContext) -> Tuple[List[Dict[str, Any]], List[str]]:
    notes: List[str] = []
    remapped: List[Dict[str, Any]] = []

    for action in actions or []:
        a = json.loads(json.dumps(action))

        if a.get("TargetGroupArn"):
            src_tg = a["TargetGroupArn"]
            tgt_tg = ctx.tg_source_to_target_arn.get(src_tg)
            if tgt_tg:
                a["TargetGroupArn"] = tgt_tg
            else:
                notes.append(f"No target TG mapping for action TargetGroupArn={src_tg}")

        fwd = a.get("ForwardConfig")
        if isinstance(fwd, dict):
            for tg in fwd.get("TargetGroups", []) or []:
                src_tg = tg.get("TargetGroupArn")
                if src_tg:
                    tgt_tg = ctx.tg_source_to_target_arn.get(src_tg)
                    if tgt_tg:
                        tg["TargetGroupArn"] = tgt_tg
                    else:
                        notes.append(f"No target TG mapping for forward TargetGroupArn={src_tg}")

        remapped.append(strip_aws_generated_keys(a))

    return canonicalize_actions(remapped), notes


def remap_certificates(cert_arns: List[str], ctx: MatchContext) -> Tuple[List[str], List[str]]:
    out: List[str] = []
    notes: List[str] = []

    for src_arn in cert_arns:
        target_arn = ctx.cert_source_to_target_arn.get(src_arn)
        if target_arn:
            out.append(target_arn)
        else:
            notes.append(f"No DR ACM certificate match for source cert {src_arn}")

    return sorted(set(out)), notes


# =============================================================================
# AUDIT
# =============================================================================

def audit_target_group(desired: TargetGroupState, live: Optional[TargetGroupState], policy: Policy) -> TargetGroupAudit:
    result = TargetGroupAudit(name=desired.name, source_arn=desired.arn, target_arn=live.arn if live else None)

    if not live:
        result.exists = False
        result.action = "CREATE"
        result.notes.append("Missing in target environment.")
        return result

    result.exists = True

    immutable_drift = diff_fields(desired.fields, live.fields, TG_IMMUTABLE_FIELDS)
    mutable_drift = diff_fields(desired.fields, live.fields, TG_MUTABLE_FIELDS)
    attribute_drift = diff_dict(desired.attributes, live.attributes, TG_SUPPORTED_ATTR_KEYS)
    tag_drift = diff_source_required_dict(desired.tags, live.tags)

    if immutable_drift:
        result.immutable_match = False
        result.immutable_drift.extend(immutable_drift)
        result.notes.append("Immutable TG drift detected. Manual rebuild may be required.")

    if mutable_drift:
        result.mutable_match = False
        result.mutable_drift.extend(mutable_drift)

    if attribute_drift:
        result.attribute_match = False
        result.attribute_drift.extend(attribute_drift)

    if tag_drift:
        result.tag_match = False
        result.tag_drift.extend(tag_drift)

    if policy.skip_target_registration:
        result.target_registration_status = "SKIPPED_DR_INSTANCES_NOT_RESTORED"
    else:
        src_count = desired.target_health_count
        tgt_count = live.target_health_count
        result.target_registration_status = "MATCH" if src_count == tgt_count else f"DRIFT source={src_count} target={tgt_count}"

    if result.requires_update:
        result.action = "UPDATE"
    elif not result.immutable_match:
        result.action = "MANUAL_REVIEW"
    else:
        result.action = "SKIP"

    return result


def audit_load_balancers(source: WorldState, target: WorldState, ctx: MatchContext, policy: Policy) -> List[ResourceAudit]:
    audits: List[ResourceAudit] = []

    for src_name, src_lb in sorted(source.load_balancers.items()):
        tgt_name = ctx.lb_source_name_to_target_name.get(src_name)
        live = target.load_balancers.get(tgt_name) if tgt_name else None

        audit = ResourceAudit(
            resource_type="load_balancer",
            name=src_name,
            source_arn=src_lb.arn,
            target_arn=live.arn if live else None,
            exists=bool(live),
        )

        if not live:
            if policy.create_missing_load_balancers:
                audit.action = "CREATE"
                audit.notes.append(
                    "Missing target load balancer. Automatic LB creation is enabled; "
                    "execution will attempt creation after subnet/security-group resolution."
                )
            else:
                audit.action = "MANUAL_REVIEW"
                audit.notes.append(
                    "Missing target load balancer. Automatic LB creation is disabled by policy."
                )
            audits.append(audit)
            continue

        immutable = diff_fields(src_lb.fields, live.fields, LB_IMMUTABLE_FIELDS)
        attrs = diff_dict(src_lb.attributes, live.attributes, LB_SUPPORTED_ATTR_KEYS)
        tag_drift = diff_source_required_dict(src_lb.tags, live.tags)

        for d in immutable:
            audit.drift.append(FieldDrift(f"immutable.{d.field}", d.source_value, d.target_value))
        for d in attrs:
            audit.drift.append(FieldDrift(f"attribute.{d.field}", d.source_value, d.target_value))
        for d in tag_drift:
            audit.drift.append(FieldDrift(f"tag.{d.field}", d.source_value, d.target_value))

        if immutable:
            audit.action = "MANUAL_REVIEW"
            audit.notes.append("Immutable LB drift detected.")
        elif attrs or tag_drift:
            audit.action = "UPDATE"
        else:
            audit.action = "SKIP"
            audit.in_sync = True

        audits.append(audit)

    return audits


def audit_target_groups(source: WorldState, target: WorldState, ctx: MatchContext, policy: Policy) -> List[TargetGroupAudit]:
    audits: List[TargetGroupAudit] = []

    for src_name, src_tg in sorted(source.target_groups.items()):
        tgt_name = ctx.tg_source_name_to_target_name.get(src_name)
        live = target.target_groups.get(tgt_name) if tgt_name else None
        audits.append(audit_target_group(src_tg, live, policy))

    return audits


def listener_key(listener: ListenerState) -> str:
    return f"{listener.protocol}:{listener.port}"


def rule_key(rule: ListenerRuleState) -> str:
    if rule.is_default:
        return "default"
    return json.dumps(rule.conditions, sort_keys=True)


def audit_listeners_and_rules(
    source: WorldState,
    target: WorldState,
    ctx: MatchContext,
    policy: Policy,
) -> Tuple[List[ResourceAudit], List[ResourceAudit]]:
    listener_audits: List[ResourceAudit] = []
    rule_audits: List[ResourceAudit] = []

    target_listener_index_by_lb: Dict[str, Dict[str, ListenerState]] = {}
    for listener in target.listeners.values():
        target_listener_index_by_lb.setdefault(
            listener.load_balancer_arn, {}
        )[listener_key(listener)] = listener

    # Helper: resolve a human-friendly certificate name from ARN
    def _cert_name_from_arn(arn: str) -> str:
        """Return DomainName or first SAN for readability."""
        for c in source.certificates.values():
            if c.arn == arn:
                domain = getattr(c, "DomainName", None)
                sans = getattr(c, "SubjectAlternativeNames", [])
                if domain:
                    return domain
                if sans:
                    return sans[0]
                return arn.split("/")[-1]  # fallback to suffix
        return arn.split("/")[-1]

    for src_lb_arn, tgt_lb_arn in sorted(ctx.lb_source_to_target_arn.items()):
        source_listeners = [
            ls for ls in source.listeners.values()
            if ls.load_balancer_arn == src_lb_arn
        ]
        target_listener_index = target_listener_index_by_lb.get(tgt_lb_arn, {})

        for src_listener in sorted(source_listeners, key=lambda x: (x.port, x.protocol)):
            key = listener_key(src_listener)
            tgt_listener = target_listener_index.get(key)

            la = ResourceAudit(
                resource_type="listener",
                name=f"{key}",
                source_arn=src_listener.arn,
                target_arn=tgt_listener.arn if tgt_listener else None,
                exists=bool(tgt_listener),
            )

            # ---------------------------------------------------------
            # CERTIFICATE REMAP + HUMAN-FRIENDLY DISPLAY
            # ---------------------------------------------------------
            desired_cert_arns, cert_notes = remap_certificates(
                src_listener.certificates, ctx
            )

            new_cert_notes: List[str] = []
            for note in cert_notes:
                arn = None
                for token in note.split():
                    if token.startswith("arn:aws:acm:"):
                        arn = token
                        break

                if arn:
                    name = _cert_name_from_arn(arn)

                    prefix = note.split(" arn:")[0].strip().lower()

                    if "expired" in prefix:
                        new_cert_notes.append(f"DR certificate for {name} is EXPIRED")
                    else:
                        new_cert_notes.append(f"No DR ACM certificate match for source certificate {name}")

                    # Add ARN as its own note line
                    new_cert_notes.append(f"ARN: {arn}")

                else:
                    new_cert_notes.append(note)

            cert_notes = new_cert_notes
            # ---------------------------------------------------------

            desired_actions, action_notes = remap_actions(
                src_listener.default_actions, ctx
            )

            for n in cert_notes + action_notes:
                la.notes.append(n)

            if not tgt_listener:
                la.action = "CREATE"
                if cert_notes or action_notes:
                    la.action = "MANUAL_REVIEW"
                listener_audits.append(la)
                continue

            drift: List[FieldDrift] = []
            if src_listener.ssl_policy != tgt_listener.ssl_policy:
                drift.append(
                    FieldDrift(
                        "SslPolicy",
                        src_listener.ssl_policy,
                        tgt_listener.ssl_policy,
                    )
                )

            if desired_cert_arns and sorted(desired_cert_arns) != sorted(
                tgt_listener.certificates
            ):
                drift.append(
                    FieldDrift(
                        "Certificates",
                        desired_cert_arns,
                        tgt_listener.certificates,
                    )
                )

            if desired_actions != canonicalize_actions(tgt_listener.default_actions):
                drift.append(
                    FieldDrift(
                        "DefaultActions",
                        desired_actions,
                        canonicalize_actions(tgt_listener.default_actions),
                    )
                )

            la.drift.extend(drift)

            if cert_notes or action_notes:
                la.action = "MANUAL_REVIEW"
            elif drift:
                la.action = "UPDATE"
            else:
                la.action = "SKIP"
                la.in_sync = True

            listener_audits.append(la)

            if not policy.sync_listener_rules:
                continue

            source_rules = [
                r
                for r in source.listener_rules.get(src_listener.arn, [])
                if not r.is_default
            ]
            target_rules = [
                r
                for r in target.listener_rules.get(tgt_listener.arn, [])
                if not r.is_default
            ]
            target_rule_index = {rule_key(r): r for r in target_rules}

            for src_rule in sorted(source_rules, key=lambda x: x.priority):
                rk = rule_key(src_rule)
                tgt_rule = target_rule_index.get(rk)

                ra = ResourceAudit(
                    resource_type="listener_rule",
                    name=f"{key}:{src_rule.priority}:{rk[:80]}",
                    source_arn=src_rule.arn,
                    target_arn=tgt_rule.arn if tgt_rule else None,
                    exists=bool(tgt_rule),
                )

                desired_actions, action_notes = remap_actions(src_rule.actions, ctx)
                for n in action_notes:
                    ra.notes.append(n)

                if not tgt_rule:
                    ra.action = "CREATE" if not action_notes else "MANUAL_REVIEW"
                    rule_audits.append(ra)
                    continue

                drift: List[FieldDrift] = []
                if desired_actions != canonicalize_actions(tgt_rule.actions):
                    drift.append(
                        FieldDrift(
                            "Actions",
                            desired_actions,
                            canonicalize_actions(tgt_rule.actions),
                        )
                    )

                if canonicalize_conditions(src_rule.conditions) != canonicalize_conditions(
                    tgt_rule.conditions
                ):
                    drift.append(
                        FieldDrift(
                            "Conditions",
                            canonicalize_conditions(src_rule.conditions),
                            canonicalize_conditions(tgt_rule.conditions),
                        )
                    )

                ra.drift.extend(drift)

                if action_notes:
                    ra.action = "MANUAL_REVIEW"
                elif drift:
                    ra.action = "UPDATE"
                else:
                    ra.action = "SKIP"
                    ra.in_sync = True

                rule_audits.append(ra)

    return listener_audits, rule_audits


# =============================================================================
# MUTATION HELPERS
# =============================================================================

def _coerce_tg_mutable_field(key: str, value: Any) -> Any:
    if key in TG_INTEGER_MUTABLE_FIELDS and value is not None:
        return int(value)
    return value


def create_target_group(elbv2: Any, desired: TargetGroupState, target_vpc_id: str, dry_run: bool, sync_tags_flag: bool) -> Optional[str]:
    name = desired.name
    payload: Dict[str, Any] = {
        "Name": name,
        "Protocol": desired.fields["Protocol"],
        "Port": int(desired.fields["Port"]),
        "VpcId": target_vpc_id,
        "TargetType": desired.fields.get("TargetType", "instance"),
    }

    for key in ["ProtocolVersion", "IpAddressType"]:
        if desired.fields.get(key):
            payload[key] = desired.fields[key]

    for key in TG_MUTABLE_FIELDS:
        value = desired.fields.get(key)
        if value is None or value == {}:
            continue
        payload[key] = _coerce_tg_mutable_field(key, value)

    if sync_tags_flag and desired.tags:
        payload["Tags"] = [{"Key": k, "Value": v} for k, v in sorted(desired.tags.items())]

    if dry_run:
        log(f"[DRY-RUN] Would create target group: {name}")
        return None

    resp = elbv2.create_target_group(**payload)
    created_groups = resp.get("TargetGroups", [])
    if not created_groups:
        raise RuntimeError(f"CreateTargetGroup returned no TargetGroups for {name}: {resp}")

    arn = created_groups[0].get("TargetGroupArn")
    if not arn:
        raise RuntimeError(f"CreateTargetGroup response missing TargetGroupArn for {name}: {created_groups[0]}")

    log(f"[CREATE-TG] {name} -> {arn}")

    if desired.attributes:
        modify_target_group_attributes(elbv2, arn, desired.attributes, dry_run=False)

    return arn


def build_tg_mutable_payload(desired: TargetGroupState, audit: TargetGroupAudit, target_arn: str) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"TargetGroupArn": target_arn}
    drift_fields = {d.field for d in audit.mutable_drift}

    for key in TG_MUTABLE_FIELDS:
        if key not in drift_fields:
            continue
        value = desired.fields.get(key)
        if value is None or value == {}:
            continue
        payload[key] = _coerce_tg_mutable_field(key, value)

    return payload


def modify_target_group(elbv2: Any, desired: TargetGroupState, audit: TargetGroupAudit, dry_run: bool) -> None:
    if not audit.target_arn:
        raise RuntimeError(f"Missing TargetGroupArn for {audit.name}")

    payload = build_tg_mutable_payload(desired, audit, audit.target_arn)

    if len(payload) == 1:
        return

    if dry_run:
        log(f"[DRY-RUN] Would modify target group settings: {audit.name}")
        return

    elbv2.modify_target_group(**payload)
    log(f"[MODIFY-TG] Updated mutable settings for {audit.name}")


def modify_target_group_attributes(
    elbv2: Any,
    target_arn: str,
    desired_attrs: Dict[str, str],
    dry_run: bool,
    drift_keys: Optional[List[str]] = None,
) -> None:
    if not desired_attrs:
        return

    keys = sorted(set(drift_keys)) if drift_keys is not None else sorted(desired_attrs.keys())
    attributes = [{"Key": key, "Value": desired_attrs[key]} for key in keys if key in desired_attrs]

    if not attributes:
        return

    if dry_run:
        log(f"[DRY-RUN] Would modify TG attributes: {target_arn} ({', '.join([a['Key'] for a in attributes])})")
        return

    elbv2.modify_target_group_attributes(TargetGroupArn=target_arn, Attributes=attributes)
    log(f"[ATTRIBUTES-TG] Updated {len(attributes)} attribute(s) on {target_arn}")


def sync_tags(elbv2: Any, arn: str, tags: Dict[str, str], dry_run: bool, label: str) -> None:
    if not tags:
        return

    payload = [{"Key": k, "Value": v} for k, v in sorted(tags.items())]

    if dry_run:
        log(f"[DRY-RUN] Would sync {len(payload)} source-required tag(s) for {label}: {arn}")
        return

    elbv2.add_tags(ResourceArns=[arn], Tags=payload)
    log(f"[TAGS] Synced {len(payload)} source-required tag(s) for {label}: {arn}")


def modify_load_balancer_attributes(elbv2: Any, target_arn: str, desired_attrs: Dict[str, str], drift: List[FieldDrift], dry_run: bool) -> None:
    keys = [d.field.replace("attribute.", "") for d in drift if d.field.startswith("attribute.")]
    attrs = [{"Key": k, "Value": desired_attrs[k]} for k in keys if k in desired_attrs]

    if not attrs:
        return

    if dry_run:
        log(f"[DRY-RUN] Would modify LB attributes: {target_arn} ({', '.join([a['Key'] for a in attrs])})")
        return

    elbv2.modify_load_balancer_attributes(LoadBalancerArn=target_arn, Attributes=attrs)
    log(f"[ATTRIBUTES-LB] Updated {len(attrs)} attribute(s) on {target_arn}")



# =============================================================================
# AUTO-MAPPING HELPERS FOR LOAD BALANCER CREATION
# =============================================================================

def _tag_value(tags: List[Dict[str, str]], key: str) -> str:
    for tag in tags or []:
        if tag.get("Key") == key:
            return str(tag.get("Value", ""))
    return ""


def _tags_to_dict(tags: List[Dict[str, str]]) -> Dict[str, str]:
    return {str(t.get("Key", "")): str(t.get("Value", "")) for t in tags or [] if t.get("Key")}


def _subnet_name(subnet: Dict[str, Any]) -> str:
    return _tag_value(subnet.get("Tags", []), "Name") or subnet.get("SubnetId", "")


def _security_group_name(sg: Dict[str, Any]) -> str:
    return _tag_value(sg.get("Tags", []), "Name") or sg.get("GroupName", "") or sg.get("GroupId", "")


def _cidr_mask(cidr: Optional[str]) -> Optional[int]:
    if not cidr or "/" not in cidr:
        return None
    try:
        return int(cidr.split("/")[-1])
    except ValueError:
        return None


def _route_has_internet_gateway(route: Dict[str, Any]) -> bool:
    gw = route.get("GatewayId", "")
    return isinstance(gw, str) and gw.startswith("igw-") and route.get("DestinationCidrBlock") == "0.0.0.0/0"


def _route_has_nat_or_gateway(route: Dict[str, Any]) -> bool:
    return (
        bool(route.get("NatGatewayId"))
        or bool(route.get("TransitGatewayId"))
        or bool(route.get("VpcPeeringConnectionId"))
        or bool(route.get("EgressOnlyInternetGatewayId"))
        or (isinstance(route.get("GatewayId"), str) and route.get("GatewayId", "").startswith("vgw-"))
    )


def _route_profile(routes: List[Dict[str, Any]]) -> str:
    """Classify subnet routing behavior for LB subnet matching."""
    has_igw = any(_route_has_internet_gateway(route) for route in routes or [])
    has_nat = any(bool(route.get("NatGatewayId")) for route in routes or [])
    has_tgw = any(bool(route.get("TransitGatewayId")) for route in routes or [])
    has_vgw = any(isinstance(route.get("GatewayId"), str) and route.get("GatewayId", "").startswith("vgw-") for route in routes or [])
    has_peer = any(bool(route.get("VpcPeeringConnectionId")) for route in routes or [])
    has_egress = any(bool(route.get("EgressOnlyInternetGatewayId")) for route in routes or [])

    if has_igw:
        return "public"
    if has_nat:
        return "private-nat"
    if has_tgw:
        return "private-tgw"
    if has_vgw:
        return "private-vgw"
    if has_peer:
        return "private-peering"
    if has_egress:
        return "private-egress-only"
    return "isolated"


def _infer_role_from_name_or_tags(name: str, tags: Dict[str, str]) -> str:
    """Infer subnet/SG role from common enterprise tag/name tokens."""
    values = [name] + list(tags.values()) + list(tags.keys())
    text = "-".join(normalize_text(str(v)) for v in values if v)

    role_groups = [
        ("public", {"public", "pub", "external", "internet", "dmz", "edge"}),
        ("private", {"private", "priv", "internal", "int"}),
        ("web", {"web", "frontend", "front-end", "fe", "alb", "elb", "ingress"}),
        ("app", {"app", "application", "middleware", "mid", "backend", "be"}),
        ("data", {"data", "db", "database", "rds", "sql", "cache", "redis"}),
        ("mgmt", {"mgmt", "management", "admin", "shared", "tools"}),
    ]
    tokens = set(text.split("-"))
    for role, needles in role_groups:
        if tokens & needles:
            return role
    return ""


def _availability_zone_letter(az_name: Optional[str]) -> str:
    if not az_name:
        return ""
    # us-west-2a -> a. This is weaker than AZ ID across accounts, but useful as a
    # tie-breaker when the DR VPC intentionally mirrors naming conventions.
    m = re.search(r"([a-z])$", az_name)
    return m.group(1) if m else ""


def _assign_az_ordinals(subnets: Dict[str, Dict[str, Any]]) -> None:
    """Assign deterministic AZ ordinal inside one VPC.

    AZ names/IDs cannot be assumed equivalent across Regions. For cross-region DR,
    the safest non-hardcoded fallback is usually ordinal placement: the first
    source AZ maps to the first target AZ, second to second, and so on after each
    VPC is sorted by stable AZ metadata. This only breaks ties; it does not
    override stronger direct AZ-ID matches.
    """
    az_keys = sorted({
        str(s.get("AvailabilityZoneId") or s.get("AvailabilityZone") or "")
        for s in subnets.values()
        if s.get("AvailabilityZoneId") or s.get("AvailabilityZone")
    })
    ordinal_by_key = {key: idx + 1 for idx, key in enumerate(az_keys)}
    for subnet in subnets.values():
        key = str(subnet.get("AvailabilityZoneId") or subnet.get("AvailabilityZone") or "")
        subnet["_AzOrdinal"] = ordinal_by_key.get(key)


def _discover_subnets_with_traits(env: Environment) -> Dict[str, Dict[str, Any]]:
    ec2 = get_ec2(env)
    subnets: Dict[str, Dict[str, Any]] = {}

    paginator = ec2.get_paginator("describe_subnets")
    for page in paginator.paginate(Filters=[{"Name": "vpc-id", "Values": [env.vpc_id]}]):
        for subnet in page.get("Subnets", []):
            subnet_id = subnet.get("SubnetId")
            if not subnet_id:
                continue
            tags = _tags_to_dict(subnet.get("Tags", []))
            name = _subnet_name(subnet)
            subnets[subnet_id] = dict(subnet)
            subnets[subnet_id]["_Tags"] = tags
            subnets[subnet_id]["_Name"] = name
            subnets[subnet_id]["_NormalizedName"] = normalize_name_for_match(name)
            subnets[subnet_id]["_Mask"] = _cidr_mask(subnet.get("CidrBlock"))
            subnets[subnet_id]["_Role"] = _infer_role_from_name_or_tags(name, tags)
            subnets[subnet_id]["_AzLetter"] = _availability_zone_letter(subnet.get("AvailabilityZone"))
            subnets[subnet_id]["_RouteProfile"] = "unknown"
            subnets[subnet_id]["_Public"] = False
            subnets[subnet_id]["_Routed"] = False

    _assign_az_ordinals(subnets)

    # Determine subnet route-table behavior. If a subnet has no explicit route-table
    # association, use the VPC main route table.
    route_tables: List[Dict[str, Any]] = []
    rt_paginator = ec2.get_paginator("describe_route_tables")
    for page in rt_paginator.paginate(Filters=[{"Name": "vpc-id", "Values": [env.vpc_id]}]):
        route_tables.extend(page.get("RouteTables", []))

    main_rt: Optional[Dict[str, Any]] = None
    explicit_by_subnet: Dict[str, Dict[str, Any]] = {}
    for rt in route_tables:
        for assoc in rt.get("Associations", []) or []:
            if assoc.get("Main"):
                main_rt = rt
            subnet_id = assoc.get("SubnetId")
            if subnet_id:
                explicit_by_subnet[subnet_id] = rt

    for subnet_id, subnet in subnets.items():
        rt = explicit_by_subnet.get(subnet_id) or main_rt
        routes = rt.get("Routes", []) if rt else []
        subnet["_RouteProfile"] = _route_profile(routes)
        subnet["_Public"] = subnet["_RouteProfile"] == "public"
        subnet["_Routed"] = any(
            route.get("DestinationCidrBlock") == "0.0.0.0/0"
            and (_route_has_internet_gateway(route) or _route_has_nat_or_gateway(route))
            for route in routes
        )

    return subnets


def _discover_security_groups_with_traits(env: Environment) -> Dict[str, Dict[str, Any]]:
    ec2 = get_ec2(env)
    groups: Dict[str, Dict[str, Any]] = {}
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate(Filters=[{"Name": "vpc-id", "Values": [env.vpc_id]}]):
        for sg in page.get("SecurityGroups", []):
            group_id = sg.get("GroupId")
            if not group_id:
                continue
            tags = _tags_to_dict(sg.get("Tags", []))
            name = _security_group_name(sg)
            groups[group_id] = dict(sg)
            groups[group_id]["_Tags"] = tags
            groups[group_id]["_Name"] = name
            groups[group_id]["_NormalizedName"] = normalize_name_for_match(name)
            groups[group_id]["_NormalizedGroupName"] = normalize_name_for_match(sg.get("GroupName", ""))
            groups[group_id]["_Role"] = _infer_role_from_name_or_tags(name, tags)
    return groups


def _score_subnet_candidate(
    source_subnet: Dict[str, Any],
    target_subnet: Dict[str, Any],
    source_region: str,
    target_region: str,
    policy: Policy,
) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []

    same_region = source_region == target_region
    src_az_id = source_subnet.get("AvailabilityZoneId")
    tgt_az_id = target_subnet.get("AvailabilityZoneId")
    src_az_name = source_subnet.get("AvailabilityZone")
    tgt_az_name = target_subnet.get("AvailabilityZone")

    # Strongest deterministic match. AZ IDs are stable across accounts in the same
    # Region, but they do not match across different Regions.
    if same_region and src_az_id and src_az_id == tgt_az_id:
        score += 140
        reasons.append(f"same-az-id={src_az_id}")

    # Same-region fallback only. AZ letters can differ across accounts, so this is
    # weaker than AZ ID.
    elif same_region and src_az_name and src_az_name == tgt_az_name:
        score += 90
        reasons.append(f"same-az-name={src_az_name}")

    # Cross-region DR fallback. AZ IDs/names are naturally different across Regions,
    # so use deterministic ordinal placement inside each VPC. This solves symmetric
    # private subnet designs where all candidates have the same route profile and CIDR.
    elif (not same_region) and policy.cross_region_az_ordinal_mapping:
        src_ord = source_subnet.get("_AzOrdinal")
        tgt_ord = target_subnet.get("_AzOrdinal")
        if src_ord and tgt_ord and src_ord == tgt_ord:
            score += 90
            reasons.append(f"az-ordinal={src_ord}")

    if source_subnet.get("_RouteProfile") == target_subnet.get("_RouteProfile"):
        score += 80
        reasons.append(f"route-profile={source_subnet.get('_RouteProfile')}")
    elif source_subnet.get("_Public") == target_subnet.get("_Public"):
        score += 45
        reasons.append(f"public={source_subnet.get('_Public')}")

    if source_subnet.get("_NormalizedName") and source_subnet.get("_NormalizedName") == target_subnet.get("_NormalizedName"):
        score += 70
        reasons.append("normalized-name")

    if source_subnet.get("_Role") and source_subnet.get("_Role") == target_subnet.get("_Role"):
        score += 35
        reasons.append(f"role={source_subnet.get('_Role')}")

    if source_subnet.get("_Mask") is not None and source_subnet.get("_Mask") == target_subnet.get("_Mask"):
        score += 20
        reasons.append(f"mask=/{source_subnet.get('_Mask')}")

    if source_subnet.get("_AzLetter") and source_subnet.get("_AzLetter") == target_subnet.get("_AzLetter"):
        score += 10
        reasons.append(f"az-letter={source_subnet.get('_AzLetter')}")

    available = target_subnet.get("AvailableIpAddressCount")
    if isinstance(available, int) and available >= 8:
        score += 5
        reasons.append("available-ip>=8")

    return score, reasons


def _select_best_scored_candidate(
    scored: List[Tuple[str, int, List[str]]],
    label: str,
    source_id: str,
    resource_name: str,
    minimum_score: int,
    tie_margin: int = 15,
) -> str:
    scored = sorted(scored, key=lambda x: (x[1], x[0]), reverse=True)
    if not scored or scored[0][1] < minimum_score:
        raise RuntimeError(
            f"No confident target {label} match for source {label} {source_id} on {resource_name}. "
            f"Best score={scored[0][1] if scored else 'none'}, required>={minimum_score}. Use explicit mappings.subnets only if multiple candidates tie or the chosen subnet is wrong."
        )

    best_id, best_score, best_reasons = scored[0]
    tied = [item for item in scored if best_score - item[1] <= tie_margin]
    if len(tied) > 1:
        details = "; ".join(
            f"{candidate_id}(score={score}, reasons={','.join(reasons)})"
            for candidate_id, score, reasons in tied[:10]
        )
        raise RuntimeError(
            f"Ambiguous target {label} match for source {label} {source_id} on {resource_name}: {details}"
        )

    log(
        f"[AUTO-MAP] {label} {source_id} -> {best_id} for {resource_name} "
        f"score={best_score} reasons={','.join(best_reasons)}"
    )
    return best_id


def _auto_match_subnet_id(
    source_subnet_id: str,
    source_subnets: Dict[str, Dict[str, Any]],
    target_subnets: Dict[str, Dict[str, Any]],
    source_region: str,
    target_region: str,
    policy: Policy,
    resource_name: str,
    already_selected: Optional[Set[str]] = None,
) -> str:
    src = source_subnets.get(source_subnet_id)
    if not src:
        raise RuntimeError(f"Could not discover source subnet {source_subnet_id} for {resource_name}")

    selected = already_selected or set()

    # vNext primary resolver: normalized subnet Name tag is the strongest
    # deterministic signal in standardized DR environments such as:
    #   Prod-App-Private-A -> app-private-a
    #   DR-App-Private-A   -> app-private-a
    # This avoids hardcoded subnet IDs while preventing generic /23 private
    # subnet ambiguity. Route profile and CIDR are used as validation only.
    src_norm_name = src.get("_NormalizedName", "")
    if src_norm_name:
        name_matches: List[Tuple[str, Dict[str, Any]]] = [
            (target_id, target_subnet)
            for target_id, target_subnet in target_subnets.items()
            if target_id not in selected and target_subnet.get("_NormalizedName") == src_norm_name
        ]
        if len(name_matches) == 1:
            target_id, target_subnet = name_matches[0]
            validation_notes: List[str] = ["normalized-name-primary"]
            if src.get("_RouteProfile") == target_subnet.get("_RouteProfile"):
                validation_notes.append(f"route-profile={src.get('_RouteProfile')}")
            elif src.get("_Public") != target_subnet.get("_Public"):
                raise RuntimeError(
                    f"Name-tag subnet match failed validation for source subnet {source_subnet_id} on {resource_name}: "
                    f"source public={src.get('_Public')} target public={target_subnet.get('_Public')} target={target_id}"
                )
            else:
                validation_notes.append(f"public={src.get('_Public')}")

            if src.get("_Mask") is not None and target_subnet.get("_Mask") is not None:
                if src.get("_Mask") != target_subnet.get("_Mask"):
                    raise RuntimeError(
                        f"Name-tag subnet match failed CIDR-mask validation for source subnet {source_subnet_id} on {resource_name}: "
                        f"source /{src.get('_Mask')} target /{target_subnet.get('_Mask')} target={target_id}"
                    )
                validation_notes.append(f"mask=/{src.get('_Mask')}")

            log(
                f"[AUTO-MAP] subnet {source_subnet_id} -> {target_id} for {resource_name} "
                f"via normalized-name={src_norm_name} validation={','.join(validation_notes)}"
            )
            return target_id

        if len(name_matches) > 1:
            details = "; ".join(
                f"{target_id}(name={target.get('_Name')}, route={target.get('_RouteProfile')}, mask=/{target.get('_Mask')})"
                for target_id, target in name_matches[:10]
            )
            raise RuntimeError(
                f"Ambiguous normalized-name subnet match for source subnet {source_subnet_id} on {resource_name}: "
                f"normalized-name={src_norm_name}; candidates={details}"
            )

    scored: List[Tuple[str, int, List[str]]] = []
    for target_id, target_subnet in target_subnets.items():
        if target_id in selected:
            continue
        score, reasons = _score_subnet_candidate(src, target_subnet, source_region, target_region, policy)
        scored.append((target_id, score, reasons))

    return _select_best_scored_candidate(
        scored=scored,
        label="subnet",
        source_id=source_subnet_id,
        resource_name=resource_name,
        minimum_score=60,
        tie_margin=10,
    )


def _auto_match_security_group_id(
    source_sg_id: str,
    source_groups: Dict[str, Dict[str, Any]],
    target_groups: Dict[str, Dict[str, Any]],
    resource_name: str,
) -> str:
    src = source_groups.get(source_sg_id)
    if not src:
        raise RuntimeError(f"Could not discover source security group {source_sg_id} for {resource_name}")

    scored: List[Tuple[str, int, List[str]]] = []
    src_norms = {src.get("_NormalizedName", ""), src.get("_NormalizedGroupName", "")}
    src_norms = {x for x in src_norms if x}

    for gid, sg in target_groups.items():
        score = 0
        reasons: List[str] = []
        target_norms = {sg.get("_NormalizedName", ""), sg.get("_NormalizedGroupName", "")}
        target_norms = {x for x in target_norms if x}
        if src_norms and src_norms & target_norms:
            score += 90
            reasons.append("normalized-name")
        if src.get("_Role") and src.get("_Role") == sg.get("_Role"):
            score += 20
            reasons.append(f"role={src.get('_Role')}")
        scored.append((gid, score, reasons))

    return _select_best_scored_candidate(
        scored=scored,
        label="security group",
        source_id=source_sg_id,
        resource_name=resource_name,
        minimum_score=90,
        tie_margin=5,
    )


def resolve_subnet_ids_for_load_balancer(
    desired: LoadBalancerState,
    config: ConfigFile,
    policy: Policy,
) -> List[str]:
    mapped: List[str] = []
    missing: List[str] = []

    for src_id in desired.subnet_ids or []:
        target_id = config.mappings.subnets.get(src_id)
        if target_id:
            mapped.append(target_id)
        else:
            missing.append(src_id)

    if missing and not policy.auto_map_subnets:
        raise RuntimeError(
            f"Missing subnet mapping(s) for {desired.name}: {', '.join(sorted(missing))}. "
            "Either add mappings.subnets or enable policy.auto_map_subnets."
        )

    if missing:
        source_subnets = _discover_subnets_with_traits(config.source)
        target_subnets = _discover_subnets_with_traits(config.target)
        selected = set(mapped)
        for src_id in missing:
            target_id = _auto_match_subnet_id(
                src_id,
                source_subnets,
                target_subnets,
                config.source.region,
                config.target.region,
                policy,
                desired.name,
                selected,
            )
            mapped.append(target_id)
            selected.add(target_id)

    return sorted(set(mapped))


def resolve_security_group_ids_for_load_balancer(
    desired: LoadBalancerState,
    config: ConfigFile,
    policy: Policy,
) -> List[str]:
    mapped: List[str] = []
    missing: List[str] = []

    for src_id in desired.security_groups or []:
        target_id = config.mappings.security_groups.get(src_id)
        if target_id:
            mapped.append(target_id)
        else:
            missing.append(src_id)

    if missing and not policy.auto_map_security_groups:
        raise RuntimeError(
            f"Missing security group mapping(s) for {desired.name}: {', '.join(sorted(missing))}. "
            "Either add mappings.security_groups or enable policy.auto_map_security_groups."
        )

    if missing:
        source_groups = _discover_security_groups_with_traits(config.source)
        target_groups = _discover_security_groups_with_traits(config.target)
        for src_id in missing:
            mapped.append(_auto_match_security_group_id(src_id, source_groups, target_groups, desired.name))

    return sorted(set(mapped))


def _map_required_ids(source_ids: List[str], mapping: Dict[str, str], label: str, resource_name: str) -> List[str]:
    """Map source environment IDs to target environment IDs, failing closed on missing mappings."""
    mapped: List[str] = []
    missing: List[str] = []

    for src_id in source_ids or []:
        target_id = mapping.get(src_id)
        if target_id:
            mapped.append(target_id)
        else:
            missing.append(src_id)

    if missing:
        raise RuntimeError(f"Missing {label} mapping(s) for {resource_name}: {', '.join(sorted(missing))}")

    return sorted(set(mapped))


def create_load_balancer(
    elbv2: Any,
    desired: LoadBalancerState,
    config: ConfigFile,
    policy: Policy,
    dry_run: bool,
    sync_tags_flag: bool,
) -> Optional[str]:
    """Create a missing target-side ALB/NLB.

    Explicit mappings are used first. If policy.auto_map_subnets and/or
    policy.auto_map_security_groups are enabled, missing mappings are resolved by
    conservative discovery. Ambiguous or missing matches fail closed.

    This intentionally does not create Route53 records, WAF associations, or target registrations.
    """
    lb_type = str(desired.fields.get("Type", "")).lower()
    if lb_type not in {"application", "network"}:
        raise RuntimeError(f"Unsupported load balancer type for {desired.name}: {lb_type!r}")

    target_subnets = resolve_subnet_ids_for_load_balancer(desired, config, policy)

    payload: Dict[str, Any] = {
        "Name": desired.name,
        "Subnets": target_subnets,
        "Scheme": desired.fields.get("Scheme", "internal"),
        "Type": lb_type,
    }

    ip_address_type = desired.fields.get("IpAddressType")
    if ip_address_type:
        payload["IpAddressType"] = ip_address_type

    # ALBs require security groups. NLB security group support is conditional and should not be
    # blindly copied unless the source object has SGs and the environment mapping is explicit.
    if lb_type == "application":
        target_sgs = resolve_security_group_ids_for_load_balancer(desired, config, policy)
        if target_sgs:
            payload["SecurityGroups"] = target_sgs

    if sync_tags_flag and desired.tags:
        payload["Tags"] = [{"Key": k, "Value": v} for k, v in sorted(desired.tags.items())]

    if dry_run:
        log(
            f"[DRY-RUN] Would create {lb_type.upper()} load balancer {desired.name} "
            f"subnets={target_subnets}"
        )
        return None

    resp = elbv2.create_load_balancer(**payload)
    created_lbs = resp.get("LoadBalancers", [])
    if not created_lbs:
        raise RuntimeError(f"CreateLoadBalancer returned no LoadBalancers for {desired.name}: {resp}")

    arn = created_lbs[0].get("LoadBalancerArn")
    if not arn:
        raise RuntimeError(f"CreateLoadBalancer response missing LoadBalancerArn for {desired.name}: {created_lbs[0]}")

    log(f"[CREATE-LB] {desired.name} -> {arn}")

    if desired.attributes:
        modify_load_balancer_attributes(
            elbv2,
            arn,
            desired.attributes,
            [FieldDrift(field=f"attribute.{k}", source_value=v, target_value=None) for k, v in desired.attributes.items()],
            dry_run=False,
        )

    return arn


# =============================================================================
# LISTENER / RULE CREATE AND UPDATE
# =============================================================================

def find_source_listener_by_arn(source: WorldState, arn: str) -> Optional[ListenerState]:
    return source.listeners.get(arn)


def find_target_lb_arn_for_source_listener(source_listener: ListenerState, ctx: MatchContext) -> Optional[str]:
    return ctx.lb_source_to_target_arn.get(source_listener.load_balancer_arn)


def create_or_update_listener(
    elbv2: Any,
    source_listener: ListenerState,
    target_listener: Optional[ListenerState],
    target_lb_arn: str,
    ctx: MatchContext,
    dry_run: bool,
) -> Optional[str]:
    actions, action_notes = remap_actions(source_listener.default_actions, ctx)
    certs, cert_notes = remap_certificates(source_listener.certificates, ctx)

    if action_notes or cert_notes:
        raise RuntimeError(f"Cannot create/update listener due to unresolved mappings: {action_notes + cert_notes}")

    if not target_listener:
        payload: Dict[str, Any] = {
            "LoadBalancerArn": target_lb_arn,
            "Protocol": source_listener.protocol,
            "Port": source_listener.port,
            "DefaultActions": actions,
        }
        if source_listener.ssl_policy:
            payload["SslPolicy"] = source_listener.ssl_policy
        if certs:
            payload["Certificates"] = [{"CertificateArn": arn} for arn in certs]

        if dry_run:
            log(f"[DRY-RUN] Would create listener {source_listener.protocol}:{source_listener.port} on {target_lb_arn}")
            return None

        resp = elbv2.create_listener(**payload)
        listener = resp.get("Listeners", [{}])[0]
        arn = listener.get("ListenerArn")
        log(f"[CREATE-LISTENER] {source_listener.protocol}:{source_listener.port} -> {arn}")
        return arn

    payload = {
        "ListenerArn": target_listener.arn,
        "DefaultActions": actions,
    }
    if source_listener.ssl_policy:
        payload["SslPolicy"] = source_listener.ssl_policy
    if certs:
        payload["Certificates"] = [{"CertificateArn": arn} for arn in certs]

    if dry_run:
        log(f"[DRY-RUN] Would update listener {target_listener.arn}")
        return target_listener.arn

    elbv2.modify_listener(**payload)
    log(f"[MODIFY-LISTENER] {target_listener.arn}")
    return target_listener.arn


def create_or_update_rule(
    elbv2: Any,
    source_rule: ListenerRuleState,
    target_rule: Optional[ListenerRuleState],
    target_listener_arn: str,
    ctx: MatchContext,
    dry_run: bool,
) -> Optional[str]:
    actions, action_notes = remap_actions(source_rule.actions, ctx)
    if action_notes:
        raise RuntimeError(f"Cannot create/update rule due to unresolved mappings: {action_notes}")

    if not target_rule:
        payload = {
            "ListenerArn": target_listener_arn,
            "Conditions": source_rule.conditions,
            "Priority": int(source_rule.priority),
            "Actions": actions,
        }
        if dry_run:
            log(f"[DRY-RUN] Would create listener rule priority={source_rule.priority} on {target_listener_arn}")
            return None

        resp = elbv2.create_rule(**payload)
        rule = resp.get("Rules", [{}])[0]
        arn = rule.get("RuleArn")
        log(f"[CREATE-RULE] priority={source_rule.priority} -> {arn}")
        return arn

    payload = {
        "RuleArn": target_rule.arn,
        "Actions": actions,
        "Conditions": source_rule.conditions,
    }

    if dry_run:
        log(f"[DRY-RUN] Would update listener rule {target_rule.arn}")
        return target_rule.arn

    elbv2.modify_rule(**payload)
    log(f"[MODIFY-RULE] {target_rule.arn}")
    return target_rule.arn


# =============================================================================
# EXECUTION
# =============================================================================

def effective_policy(args: Args, policy: Policy) -> Policy:
    p = Policy(**asdict(policy))
    if args.no_create_missing_tg:
        p.create_missing_target_groups = False
    if args.no_create_missing_lb:
        p.create_missing_load_balancers = False
    if args.no_sync_tags:
        p.sync_tags = False
    if args.no_sync_listener_rules:
        p.sync_listener_rules = False
    if args.skip_target_registration:
        p.skip_target_registration = True
        p.register_targets = False
    return p


def execute_plan(
    args: Args,
    config: ConfigFile,
    source: WorldState,
    target: WorldState,
    ctx: MatchContext,
    tg_audits: List[TargetGroupAudit],
    lb_audits: List[ResourceAudit],
    listener_audits: List[ResourceAudit],
    rule_audits: List[ResourceAudit],
) -> ExecutionContext:
    context = ExecutionContext()
    elbv2 = get_elbv2(config.target)
    policy = effective_policy(args, config.policy)

    log("\n================ ELBV2 EXECUTION START ================")

    # 1. Target Groups
    for audit in tg_audits:
        desired = source.target_groups.get(audit.name)
        if not desired:
            continue

        try:
            if audit.action == "CREATE":
                if args.no_create_missing_tg or not policy.create_missing_target_groups:
                    log(f"[SKIP] Missing TG creation disabled for {audit.name}")
                    continue
                arn = create_target_group(elbv2, desired, config.target.vpc_id, args.dry_run, sync_tags_flag=not args.no_sync_tags and policy.sync_tags)
                if arn:
                    context.created_target_groups.append(audit.name)
                    context.rollback_actions.append({"operation": "delete_target_group", "target_group_arn": arn, "target_group_name": audit.name})
                continue

            if audit.action == "UPDATE":
                if audit.mutable_drift and policy.sync_target_group_settings:
                    modify_target_group(elbv2, desired, audit, args.dry_run)
                if audit.attribute_drift and audit.target_arn and policy.sync_target_group_attributes:
                    drift_keys = [d.field for d in audit.attribute_drift]
                    modify_target_group_attributes(elbv2, audit.target_arn, desired.attributes, args.dry_run, drift_keys=drift_keys)
                if audit.tag_drift and not args.no_sync_tags and policy.sync_tags and audit.target_arn:
                    sync_tags(elbv2, audit.target_arn, desired.tags, args.dry_run, "target-group")
                context.updated_target_groups.append(audit.name)

        except Exception as exc:
            eprint(f"[ERROR] Failed TG action for {audit.name}: {exc}")
            context.failed_actions.append({"resource_type": "target_group", "name": audit.name, "error": str(exc)})

    # Refresh state after TG creation
    if any(a.action == "CREATE" for a in tg_audits) and not args.dry_run:
        target = discover_world(config.target)
        ctx = build_match_context(source, target, allow_legacy=args.allow_legacy, policy=policy, mappings=config.mappings)

    # 2. Load balancers
    for audit in lb_audits:
        src_lb = source.load_balancers.get(audit.name)
        target_arn = audit.target_arn

        try:
            if audit.action == "CREATE":
                if args.no_create_missing_lb or not policy.create_missing_load_balancers:
                    log(f"[SKIP] Missing LB creation disabled for {audit.name}")
                    continue
                if not src_lb:
                    raise RuntimeError(f"Source LB state not found for {audit.name}")
                arn = create_load_balancer(
                    elbv2,
                    src_lb,
                    config,
                    policy,
                    args.dry_run,
                    sync_tags_flag=not args.no_sync_tags and policy.sync_tags,
                )
                if arn:
                    context.created_load_balancers.append(audit.name)
                    context.rollback_actions.append({
                        "operation": "delete_load_balancer",
                        "load_balancer_arn": arn,
                        "load_balancer_name": audit.name,
                    })
                continue

            if audit.action == "UPDATE" and src_lb and target_arn:
                attr_drifts = [d for d in audit.drift if d.field.startswith("attribute.")]
                tag_drifts = [d for d in audit.drift if d.field.startswith("tag.")]
                if attr_drifts and policy.sync_load_balancer_attributes:
                    modify_load_balancer_attributes(elbv2, target_arn, src_lb.attributes, audit.drift, args.dry_run)
                if tag_drifts and not args.no_sync_tags and policy.sync_tags:
                    sync_tags(elbv2, target_arn, src_lb.tags, args.dry_run, "load-balancer")
                context.updated_load_balancers.append(audit.name)

        except Exception as exc:
            eprint(f"[ERROR] Failed LB action for {audit.name}: {exc}")
            context.failed_actions.append({"resource_type": "load_balancer", "name": audit.name, "error": str(exc)})

    # Refresh state after LB creation because listeners depend on target LB ARNs.
    if any(a.action == "CREATE" for a in lb_audits) and not args.dry_run:
        target = discover_world(config.target)
        ctx = build_match_context(source, target, allow_legacy=args.allow_legacy, policy=policy, mappings=config.mappings)
        # Re-audit downstream resources so listeners/rules under newly-created LBs are included.
        listener_audits, rule_audits = audit_listeners_and_rules(source, target, ctx, policy)

    # 3. Listeners
    if policy.sync_listeners:
        for audit in listener_audits:
            if audit.action not in {"CREATE", "UPDATE"}:
                continue

            src_listener = find_source_listener_by_arn(source, audit.source_arn or "")
            if not src_listener:
                continue

            target_lb_arn = find_target_lb_arn_for_source_listener(src_listener, ctx)
            if not target_lb_arn:
                context.failed_actions.append({"resource_type": "listener", "name": audit.name, "error": "No target LB mapping"})
                continue

            target_listener = target.listeners.get(audit.target_arn or "")

            try:
                arn = create_or_update_listener(elbv2, src_listener, target_listener, target_lb_arn, ctx, args.dry_run)
                if audit.action == "CREATE":
                    context.created_listeners.append(audit.name)
                    if arn:
                        context.rollback_actions.append({"operation": "delete_listener", "listener_arn": arn})
                else:
                    context.updated_listeners.append(audit.name)
            except Exception as exc:
                eprint(f"[ERROR] Failed listener action for {audit.name}: {exc}")
                context.failed_actions.append({"resource_type": "listener", "name": audit.name, "error": str(exc)})

    # Refresh listeners after changes
    if listener_audits and not args.dry_run:
        target = discover_world(config.target)
        ctx = build_match_context(source, target, allow_legacy=args.allow_legacy, policy=policy, mappings=config.mappings)

    # 4. Listener rules
    if policy.sync_listener_rules:
        target_listener_index_by_lb: Dict[str, Dict[str, ListenerState]] = {}
        for listener in target.listeners.values():
            target_listener_index_by_lb.setdefault(listener.load_balancer_arn, {})[listener_key(listener)] = listener

        for audit in rule_audits:
            if audit.action not in {"CREATE", "UPDATE"}:
                continue

            src_rule = None
            src_listener = None
            for listener_arn, rules in source.listener_rules.items():
                for rule in rules:
                    if rule.arn == audit.source_arn:
                        src_rule = rule
                        src_listener = source.listeners.get(listener_arn)
                        break
                if src_rule:
                    break

            if not src_rule or not src_listener:
                continue

            target_lb_arn = ctx.lb_source_to_target_arn.get(src_listener.load_balancer_arn)
            if not target_lb_arn:
                context.failed_actions.append({"resource_type": "listener_rule", "name": audit.name, "error": "No target LB mapping"})
                continue

            target_listener = target_listener_index_by_lb.get(target_lb_arn, {}).get(listener_key(src_listener))
            if not target_listener:
                context.failed_actions.append({"resource_type": "listener_rule", "name": audit.name, "error": "No target listener found"})
                continue

            target_rule = None
            if audit.target_arn:
                for r in target.listener_rules.get(target_listener.arn, []):
                    if r.arn == audit.target_arn:
                        target_rule = r
                        break

            try:
                arn = create_or_update_rule(elbv2, src_rule, target_rule, target_listener.arn, ctx, args.dry_run)
                if audit.action == "CREATE":
                    context.created_listener_rules.append(audit.name)
                    if arn:
                        context.rollback_actions.append({"operation": "delete_rule", "rule_arn": arn})
                else:
                    context.updated_listener_rules.append(audit.name)
            except Exception as exc:
                eprint(f"[ERROR] Failed listener rule action for {audit.name}: {exc}")
                context.failed_actions.append({"resource_type": "listener_rule", "name": audit.name, "error": str(exc)})

    log("================ ELBV2 EXECUTION COMPLETE ================\n")
    return context

# =============================================================================
# REPORTING
# =============================================================================

def audit_summary(
    tg: List[TargetGroupAudit],
    lb: List[ResourceAudit],
    listeners: List[ResourceAudit],
    rules: List[ResourceAudit],
    ctx: MatchContext,
) -> Dict[str, Any]:
    all_resources = list(lb) + list(listeners) + list(rules)
    return {
        "target_groups_total": len(tg),
        "target_groups_in_sync": len([x for x in tg if x.in_sync]),
        "target_groups_create": len([x for x in tg if x.action == "CREATE"]),
        "target_groups_update": len([x for x in tg if x.action == "UPDATE"]),
        "target_groups_manual_review": len([x for x in tg if x.action == "MANUAL_REVIEW"]),
        "load_balancers_total": len(lb),
        "load_balancers_in_sync": len([x for x in lb if x.in_sync]),
        "listeners_total": len(listeners),
        "listeners_in_sync": len([x for x in listeners if x.in_sync]),
        "listener_rules_total": len(rules),
        "listener_rules_in_sync": len([x for x in rules if x.in_sync]),
        "create_total": len([x for x in all_resources if x.action == "CREATE"]) + len([x for x in tg if x.action == "CREATE"]),
        "update_total": len([x for x in all_resources if x.action == "UPDATE"]) + len([x for x in tg if x.action == "UPDATE"]),
        "manual_review_total": len([x for x in all_resources if x.action == "MANUAL_REVIEW"]) + len([x for x in tg if x.action == "MANUAL_REVIEW"]),
        "ambiguous_matches": len(ctx.ambiguous),
        "unmatched_resources": len(ctx.unmatched),
    }


def resource_to_dict(item: Any) -> Dict[str, Any]:
    data = asdict(item)
    if isinstance(item, TargetGroupAudit):
        data["in_sync"] = item.in_sync
        data["requires_create"] = item.requires_create
        data["requires_update"] = item.requires_update
    return data


def resolve_report_path(args: Args, config: ConfigFile) -> str:
    # If user explicitly provided a path, use it as-is
    if args.report_path:
        return args.report_path

    # Ensure the directory exists
    ensure_dir(args.report_dir)

    # Determine mode for filename
    mode = "dryrun" if args.dry_run else "apply" if args.yes else "report"

    # Build timestamped filename
    filename = (
        f"elbv2_reconcile_{mode}_"
        f"{config.target.profile or 'default'}_"
        f"{config.target.region}_"
        f"{now_stamp()}.json"
    )

    # Full path inside the report directory
    return os.path.join(args.report_dir, filename)


def print_report(
    tg_audits: List[TargetGroupAudit],
    lb_audits: List[ResourceAudit],
    listener_audits: List[ResourceAudit],
    rule_audits: List[ResourceAudit],
    ctx: MatchContext,
) -> None:
    summary = audit_summary(tg_audits, lb_audits, listener_audits, rule_audits, ctx)

    print("\n" + "=" * 100)
    print("ELBV2 DR ROUTING RECONCILIATION REPORT")
    print("=" * 100)
    for key, value in summary.items():
        print(f"{key:36}: {value}")

    if ctx.ambiguous:
        print("\n[AMBIGUOUS MATCHES]")
        for item in ctx.ambiguous:
            print(f" - {item['resource_type']}: {item['source']} -> {item['candidates']}")

    attention_tg = [r for r in tg_audits if not r.in_sync]
    attention_res = [r for r in list(lb_audits) + list(listener_audits) + list(rule_audits) if not r.in_sync]

    if not attention_tg and not attention_res:
        print("\nAll discovered ELBv2 routing resources are in sync.")
        print("=" * 100)
        return

    for r in attention_tg:
        print("\n" + "-" * 100)
        print(f"TG: {r.name}")
        print(f"Action                 : {r.action}")
        print(f"Exists                 : {r.exists}")
        print(f"Immutable              : {'OK' if r.immutable_match else 'DRIFT'}")
        print(f"Mutable                : {'OK' if r.mutable_match else 'DRIFT'}")
        print(f"Attributes             : {'OK' if r.attribute_match else 'DRIFT'}")
        print(f"Tags                   : {'OK' if r.tag_match else 'DRIFT'}")
        print(f"Target registration    : {r.target_registration_status}")
        for title, drifts in [
            ("Immutable drift", r.immutable_drift),
            ("Mutable drift", r.mutable_drift),
            ("Attribute drift", r.attribute_drift),
            ("Tag drift", r.tag_drift),
        ]:
            if not drifts:
                continue
            print(f"{title}:")
            for drift in drifts:
                print(f"  - {drift.field}: source={drift.source_value!r}, target={drift.target_value!r}")
        for note in r.notes:
            print(f"Note: {note}")

    for r in attention_res:
        print("\n" + "-" * 100)
        print(f"{r.resource_type.upper()}: {r.name}")
        print(f"Action     : {r.action}")
        print(f"Exists     : {r.exists}")
        if r.drift:
            print("Drift:")
            for d in r.drift:
                print(f"  - {d.field}: source={d.source_value!r}, target={d.target_value!r}")
        if r.notes:
            print("Notes:")
            for n in r.notes:
                print(f"  - {n}")

    print("=" * 100)


def build_report_payload(
    args: Args,
    config: ConfigFile,
    policy: Policy,
    source: WorldState,
    target: WorldState,
    ctx: MatchContext,
    tg_audits: List[TargetGroupAudit],
    lb_audits: List[ResourceAudit],
    listener_audits: List[ResourceAudit],
    rule_audits: List[ResourceAudit],
    context: Optional[ExecutionContext],
    post_apply_validation: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "created_at_utc": utc_now_iso(),
        "mode": {"dry_run": args.dry_run, "report_only": args.report_only, "yes": args.yes},
        "source": asdict(config.source),
        "target": asdict(config.target),
        "effective_policy": asdict(policy),
        "discovery_counts": {
            "source": {
                "load_balancers": len(source.load_balancers),
                "listeners": len(source.listeners),
                "listener_rules": sum(len(v) for v in source.listener_rules.values()),
                "target_groups": len(source.target_groups),
                "certificates": len(source.certificates),
            },
            "target": {
                "load_balancers": len(target.load_balancers),
                "listeners": len(target.listeners),
                "listener_rules": sum(len(v) for v in target.listener_rules.values()),
                "target_groups": len(target.target_groups),
                "certificates": len(target.certificates),
            },
        },
        "summary": audit_summary(tg_audits, lb_audits, listener_audits, rule_audits, ctx),
        "matches": asdict(ctx),
        "target_group_results": [resource_to_dict(r) for r in tg_audits],
        "load_balancer_results": [resource_to_dict(r) for r in lb_audits],
        "listener_results": [resource_to_dict(r) for r in listener_audits],
        "listener_rule_results": [resource_to_dict(r) for r in rule_audits],
        "execution": asdict(context) if context else {
            "created_target_groups": [],
            "created_load_balancers": [],
            "created_listeners": [],
            "created_listener_rules": [],
            "updated_target_groups": [],
            "updated_load_balancers": [],
            "updated_listeners": [],
            "updated_listener_rules": [],
            "failed_actions": [],
            "rollback_actions": [],
        },
        "post_apply_validation": post_apply_validation or {
            "enabled": False,
            "status": "NOT_RUN",
            "passed": None,
            "reason": "Post-apply validation only runs after --yes apply mode.",
        },
    }


def run_post_apply_validation(args: Args, config: ConfigFile) -> Dict[str, Any]:
    log("\n================ POST-APPLY VALIDATION START ================")
    source = discover_world(config.source)
    target = discover_world(config.target)
    policy = effective_policy(args, config.policy)
    ctx = build_match_context(source, target, allow_legacy=args.allow_legacy, policy=policy, mappings=config.mappings)

    tg = audit_target_groups(source, target, ctx, policy)
    lb = audit_load_balancers(source, target, ctx, policy)
    listeners, rules = audit_listeners_and_rules(source, target, ctx, policy)

    summary = audit_summary(tg, lb, listeners, rules, ctx)
    passed = (
        summary["create_total"] == 0
        and summary["update_total"] == 0
        and summary["manual_review_total"] == 0
        and summary["ambiguous_matches"] == 0
    )
    status = "PASSED" if passed else "FAILED"

    log(
        f"[POST-APPLY-VALIDATION] status={status}, "
        f"create={summary['create_total']}, update={summary['update_total']}, "
        f"manual_review={summary['manual_review_total']}, ambiguous={summary['ambiguous_matches']}"
    )
    log("================ POST-APPLY VALIDATION COMPLETE ================\n")

    return {
        "enabled": True,
        "status": status,
        "passed": passed,
        "summary": summary,
        "matches": asdict(ctx),
        "target_group_results": [resource_to_dict(r) for r in tg],
        "load_balancer_results": [resource_to_dict(r) for r in lb],
        "listener_results": [resource_to_dict(r) for r in listeners],
        "listener_rule_results": [resource_to_dict(r) for r in rules],
    }


# =============================================================================
# ARGS
# =============================================================================

def parse_args() -> Args:
    parser = argparse.ArgumentParser(description="Enterprise AWS ELBv2 DR Routing Reconciliation Engine vNext")
    parser.add_argument("--info-file", required=True, help="Path to source/target config JSON")

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Preview actions without modifying AWS")
    mode.add_argument("--report-only", action="store_true", help="Build report only; do not execute actions")
    mode.add_argument("--yes", action="store_true", help="Apply changes and run post-apply validation")

    parser.add_argument("--allow-legacy", action="store_true", help="Allow normalized-name fallback matching")
    parser.add_argument("--no-create-missing-tg", action="store_true", help="Do not create missing target groups")
    parser.add_argument("--no-create-missing-lb", action="store_true", help="Do not create missing load balancers")
    parser.add_argument("--no-sync-tags", action="store_true", help="Do not sync source-required tags")
    parser.add_argument("--no-sync-listener-rules", action="store_true", help="Do not create/update listener rules")
    parser.add_argument("--skip-target-registration", action="store_true", default=True, help="Treat target registration as skipped/warning only")
    parser.add_argument("--report-path", default="", help="Optional explicit report output path")
    parser.add_argument("--report-dir", default=DEFAULT_REPORT_DIR, help="Report directory")
    parser.add_argument("--rollback-dir", default=DEFAULT_ROLLBACK_DIR, help="Rollback journal directory")
    parser.add_argument("--debug-discovery", action="store_true", help="Print per-LB/listener discovery details, including AWS rule counts and normalized rules")

    ns = parser.parse_args()

    if not ns.dry_run and not ns.report_only and not ns.yes:
        ns.dry_run = True

    return Args(
        ns.info_file,
        ns.dry_run,
        ns.report_only,
        ns.yes,
        ns.allow_legacy,
        ns.no_create_missing_tg,
        ns.no_create_missing_lb,
        ns.no_sync_tags,
        ns.no_sync_listener_rules,
        ns.skip_target_registration,
        ns.report_path,
        ns.report_dir,
        ns.rollback_dir,
        ns.debug_discovery,
    )


def write_human_report(
    path: str,
    summary: Dict[str, Any],
    tg_audits: List[Any],
    lb_audits: List[Any],
    listener_audits: List[Any],
    rule_audits: List[Any],
    ctx: Any,
) -> None:
    lines = []

    # Header
    lines.append("ELBv2 DR RECONCILIATION – HUMAN READABLE REPORT")
    lines.append("=" * 70)
    lines.append(f"Created: {utc_now_iso()}")
    lines.append("")

    # Executive Summary
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 70)
    lines.append(f"Target Groups: {summary['target_groups_in_sync']}/{summary['target_groups_total']} in sync")
    lines.append(f"Load Balancers: {summary['load_balancers_in_sync']}/{summary['load_balancers_total']} in sync")
    lines.append(f"Listeners: {summary['listeners_in_sync']}/{summary['listeners_total']} in sync")
    lines.append(f"Manual Review Required: {summary['manual_review_total']}")
    lines.append(f"Ambiguous Matches: {summary['ambiguous_matches']}")
    lines.append(f"Unmatched Resources: {summary['unmatched_resources']}")
    lines.append("")

    # Target Groups
    lines.append("TARGET GROUPS")
    lines.append("-" * 70)
    for tg in tg_audits:
        status = "OK" if tg.in_sync else "DRIFT"
        lines.append(f"{tg.name:40} {status}")
    lines.append("")

    # Load Balancer Drift
    lines.append("LOAD BALANCER DRIFT")
    lines.append("-" * 70)
    for lb in lb_audits:
        if lb.in_sync:
            continue
        lines.append(f"{lb.name} – {lb.action}")
        for d in lb.drift:
            lines.append(f"  • {d.field}: {d.source_value} → {d.target_value}")
        for n in lb.notes:
            lines.append(f"  Note: {n}")
        lines.append("")
    lines.append("")

    # Listener Drift
    lines.append("LISTENER DRIFT")
    lines.append("-" * 70)
    for ls in listener_audits:
        if ls.in_sync:
            continue
        lines.append(f"{ls.name} – {ls.action}")
        for d in ls.drift:
            lines.append(f"  • {d.field}: {d.source_value} → {d.target_value}")
        for n in ls.notes:
            lines.append(f"  Note: {n}")
        lines.append("")
    lines.append("")

    # Write file
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def cert_display_name_hybrid(cert):
    """Return a hybrid human-friendly certificate name: domain + ARN suffix."""
    if not cert:
        return "UNKNOWN-CERT"

    domain = getattr(cert, "DomainName", None)
    sans = getattr(cert, "SubjectAlternativeNames", [])
    arn = getattr(cert, "CertificateArn", "")

    # Extract ARN suffix
    suffix = arn.split("/")[-1] if arn else "unknown"

    # Prefer primary domain
    if domain:
        return f"{domain} ({suffix})"

    # Fallback to first SAN
    if sans:
        return f"{sans[0]} ({suffix})"

    # Fallback to suffix only
    return suffix



# =============================================================================
# vNext DISCOVERY DIAGNOSTICS
# =============================================================================

def print_discovery_diagnostics(source: WorldState, target: WorldState, ctx: MatchContext) -> None:
    print("\n" + "=" * 100)
    print("ELBV2 vNext DISCOVERY DIAGNOSTICS")
    print("=" * 100)
    print(f"Source: LBs={len(source.load_balancers)}, listeners={len(source.listeners)}, rules={sum(len(v) for v in source.listener_rules.values())}, TGs={len(source.target_groups)}, certs={len(source.certificates)}")
    print(f"Target: LBs={len(target.load_balancers)}, listeners={len(target.listeners)}, rules={sum(len(v) for v in target.listener_rules.values())}, TGs={len(target.target_groups)}, certs={len(target.certificates)}")

    print("\nLOAD BALANCER / LISTENER / RULE INVENTORY")
    print("-" * 100)

    source_listeners_by_lb: Dict[str, List[ListenerState]] = {}
    for ls in source.listeners.values():
        source_listeners_by_lb.setdefault(ls.load_balancer_arn, []).append(ls)

    target_listeners_by_lb: Dict[str, List[ListenerState]] = {}
    for ls in target.listeners.values():
        target_listeners_by_lb.setdefault(ls.load_balancer_arn, []).append(ls)

    for src_lb_name, src_lb in sorted(source.load_balancers.items()):
        tgt_lb_name = ctx.lb_source_name_to_target_name.get(src_lb_name)
        tgt_lb = target.load_balancers.get(tgt_lb_name) if tgt_lb_name else None
        print(f"\nLB: {src_lb_name}")
        print(f"  Source ARN : {src_lb.arn}")
        print(f"  Target     : {tgt_lb_name or 'UNMATCHED'}")
        if tgt_lb:
            print(f"  Target ARN : {tgt_lb.arn}")

        src_listeners = sorted(source_listeners_by_lb.get(src_lb.arn, []), key=lambda x: (x.protocol, x.port))
        tgt_listener_index: Dict[str, ListenerState] = {}
        if tgt_lb:
            for tls in target_listeners_by_lb.get(tgt_lb.arn, []):
                tgt_listener_index[f"{tls.protocol}:{tls.port}"] = tls

        if not src_listeners:
            print("  Source listeners: 0")
            continue

        for sls in src_listeners:
            key = f"{sls.protocol}:{sls.port}"
            tls = tgt_listener_index.get(key)
            src_rules = source.listener_rules.get(sls.arn, [])
            tgt_rules = target.listener_rules.get(tls.arn, []) if tls else []
            src_non_default = [r for r in src_rules if not r.is_default]
            tgt_non_default = [r for r in tgt_rules if not r.is_default]
            print(f"  Listener {key}")
            print(f"    Source rules: total={len(src_rules)}, non_default={len(src_non_default)}, priorities={[r.priority for r in src_rules]}")
            if tls:
                print(f"    Target rules: total={len(tgt_rules)}, non_default={len(tgt_non_default)}, priorities={[r.priority for r in tgt_rules]}")
            else:
                print("    Target rules: listener unmatched")

    print("=" * 100)

# =============================================================================
# MAIN
# =============================================================================

def main() -> int:
    args = parse_args()

    try:
        log("\n============================================================")
        log(" Enterprise AWS ELBv2 DR Routing Reconciliation Engine vNext")
        log("============================================================")

        config = load_config(args.info_file)
        policy = effective_policy(args, config.policy)

        log(f"[SOURCE] profile={config.source.profile}, region={config.source.region}, vpc={config.source.vpc_id}")
        log(f"[TARGET] profile={config.target.profile}, region={config.target.region}, vpc={config.target.vpc_id}")
        log(f"[MODE] dry_run={args.dry_run}, report_only={args.report_only}, yes={args.yes}")
        log(f"[POLICY] {json.dumps(asdict(policy), sort_keys=True)}")

        log("[INFO] Discovering source ELBv2 world")
        source = discover_world(config.source)
        log(
            f"[SOURCE] LBs={len(source.load_balancers)}, listeners={len(source.listeners)}, "
            f"rules={sum(len(v) for v in source.listener_rules.values())}, TGs={len(source.target_groups)}, certs={len(source.certificates)}"
        )

        log("[INFO] Discovering target ELBv2 world")
        target = discover_world(config.target)
        log(
            f"[TARGET] LBs={len(target.load_balancers)}, listeners={len(target.listeners)}, "
            f"rules={sum(len(v) for v in target.listener_rules.values())}, TGs={len(target.target_groups)}, certs={len(target.certificates)}"
        )

        ctx = build_match_context(source, target, allow_legacy=args.allow_legacy, policy=policy, mappings=config.mappings)

        if args.debug_discovery:
            print_discovery_diagnostics(source, target, ctx)

        tg_audits = audit_target_groups(source, target, ctx, policy)
        lb_audits = audit_load_balancers(source, target, ctx, policy)
        listener_audits, rule_audits = audit_listeners_and_rules(source, target, ctx, policy)

        print_report(tg_audits, lb_audits, listener_audits, rule_audits, ctx)

        context: Optional[ExecutionContext] = None
        post_apply_validation: Optional[Dict[str, Any]] = None

        if args.report_only:
            log("[REPORT-ONLY] No execution will be attempted.")
        else:
            context = execute_plan(
                args,
                config,
                source,
                target,
                ctx,
                tg_audits,
                lb_audits,
                listener_audits,
                rule_audits,
            )

            if args.yes:
                post_apply_validation = run_post_apply_validation(args, config)

        report_payload = build_report_payload(
            args,
            config,
            policy,
            source,
            target,
            ctx,
            tg_audits,
            lb_audits,
            listener_audits,
            rule_audits,
            context,
            post_apply_validation,
        )

        report_path = resolve_report_path(args, config)
        write_json(report_path, report_payload)
        log(f"[REPORT] Written: {report_path}")

        # -------------------------------------------------------------------------
        # HUMAN‑READABLE REPORT
        # -------------------------------------------------------------------------
        human_report_path = report_path.replace(".json", ".txt")
        write_human_report(
            human_report_path,
            report_payload["summary"],
            tg_audits,
            lb_audits,
            listener_audits,
            rule_audits,
            ctx
        )
        log(f"[REPORT] Human-readable report written: {human_report_path}")
        # -------------------------------------------------------------------------

        log("[DONE] ELBv2 DR routing reconciliation complete.")
        return 0

    except KeyboardInterrupt:
        eprint("\n[ABORTED] Interrupted by user.")
        return 130
    except Exception as exc:
        eprint(f"\n[FATAL] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())