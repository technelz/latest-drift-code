1. Overview
The ELB/ALB Disaster Recovery Sync Tool compares and synchronizes AWS Application Load Balancer (ALB) and Network Load Balancer (NLB) configurations between a source region and a DR region.

It performs:

Load balancer discovery

Listener comparison

Listener rule drift detection

Target group sync

Certificate matching

Tag synchronization

Attribute comparison

Health check sync

The tool produces a human‑readable drift report and can optionally apply changes to bring the DR region into alignment.

2. Architecture & Behavior
The tool operates in four phases:

2.1 World State Discovery
The tool queries AWS APIs in both regions to collect:

Load balancers

Listeners

Listener rules

Target groups

Certificates

Tags

Attributes

Health checks

This forms the “source state” and “DR state”.

2.2 Match Context
The tool builds deterministic mappings using:

ARN matching

Name matching

Certificate domain/SAN matching

Policy rules from the infofile

This produces a source → target relationship for all components.

2.3 Audit Engine
The audit engine identifies:

Missing resources

Drifted configuration

Extra DR resources

Manual review cases

Each item is assigned an action:

CREATE

UPDATE

DELETE

SKIP

MANUAL_REVIEW

2.4 Apply Engine (Optional)
Runs only when the user explicitly chooses:

Code
--apply --yes
The Apply Engine:

Creates missing resources

Updates drifted resources

Syncs listeners, rules, TGs, attributes, and tags

Honors all policy settings

3. Configuration File (elb_config.json)
The infofile controls behavior, not resource definitions.

Example
Code
{
  "source": {
    "profile": "default",
    "region": "us-west-2",
    "vpc_id": "vpc-prod"
  },
  "target": {
    "profile": "dr-cadbo",
    "region": "us-east-1",
    "vpc_id": "vpc-dr"
  },
  "policy": {
    "register_targets": false,
    "create_missing_load_balancers": false,
    "create_missing_target_groups": true,
    "sync_load_balancer_attributes": true,
    "sync_target_group_attributes": true,
    "sync_target_group_settings": true,
    "sync_listener_rules": true,
    "sync_listeners": true,
    "sync_tags": true,
    "allow_extra_target_rules": true,
    "skip_target_registration": true,
    "allow_certificate_domain_match": true
  }
}
4. Command‑Line Interface (Actual Behavior)
Your script supports only the arguments shown in its usage:

Code
--info-file INFO_FILE   (required)
--dry-run | --report-only | --yes  (mutually exclusive)
--apply
--allow-legacy
--no-create-missing-tg
--no-create-missing-lb
--no-sync-tags
--no-sync-listener-rules
--skip-target-registration
--report-path
--report-dir
--rollback-dir
❗ Flags that DO NOT exist (despite the old runbook):
--audit

--verbose

--infofile (must be --info-file)

--apply --dry-run (mutually exclusive)

5. Supported Modes
5.1 Audit Mode (Safe)
This is the primary non‑destructive mode.

Code
python elbv2_reconcile_engine.py --info-file elb_config.json --dry-run
What it does:

Performs full discovery

Runs the audit engine

Prints drift report

Makes no changes

This is the correct replacement for the old “--audit” flag.

5.2 Apply Mode (Dangerous)
Applies changes to DR.

Code
python elbv2_reconcile_engine.py --info-file elb_config.json --apply --yes
--apply enables the Apply Engine

--yes confirms changes

Without --yes, the tool stays in audit mode

5.3 Report‑Only Mode
Generates a report without drift logic.

Code
python elbv2_reconcile_engine.py --info-file elb_config.json --report-only
6. Output Example
Code
Listener: 443/HTTPS
  Action: UPDATE
  Drift:
    - Certificates differ
  Notes:
    - No DR ACM certificate match for source certificate api.example.com
    - Certificate ARN: arn:aws:acm:us-west-2:123:certificate/abcd1234
7. Manual Review Cases
Some situations require human judgment:

Certificate domain mismatch

Ambiguous listener rule conditions

Conflicting TG settings

Unsafe deletes

These appear as:

Code
Action: MANUAL_REVIEW
8. Operational Guidance
8.1 When to Run Audit
Run audit:

Before DR drills

After major ALB/NLB changes

Before enabling apply mode

Monthly as part of DR hygiene

8.2 When to Run Apply
Run apply:

During DR parity maintenance

After validating audit output

During DR cutover preparation

Never run apply without reviewing the drift report.

8.3 Rollback
If the tool supports rollback directories:

Code
--rollback-dir ./rollback
This stores pre‑change state for manual rollback.

9. Troubleshooting
Problem: “unrecognized arguments: --audit”
Cause: The script does not implement --audit.

Fix: Use:

Code
--dry-run
Problem: “unrecognized arguments: --verbose”
Cause: No verbose flag exists.

Fix: None — not supported.

Problem: “the following arguments are required: --info-file”
Cause: You used --infofile.

Fix: Use:

Code
--info-file
10. Quick Reference
Task	Command
Audit (safe)	python elbv2_reconcile_engine.py --info-file elb_config.json --dry-run
Apply (dangerous)	python elbv2_reconcile_engine.py --info-file elb_config.json --apply --yes
Report only	python elbv2_reconcile_engine.py --info-file elb_config.json --report-only
Specify report directory	--report-dir ./reports
Specify rollback directory	--rollback-dir ./rollback