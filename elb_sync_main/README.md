ELB/ALB Disaster Recovery Sync Tool
A cross‑region drift detection and synchronization engine for AWS Load Balancers

📘 Overview
The ELB/ALB Disaster Recovery Sync Tool compares and synchronizes AWS Application Load Balancer (ALB) and Network Load Balancer (NLB) configurations between a source region and a disaster recovery (DR) region.

It performs a full audit of:

Load balancers

Listeners

Listener rules

Target groups

Certificates

Tags

Attributes

Health checks

The tool produces a human‑readable drift report and can optionally apply changes to bring the DR region into sync.

✨ Features
Dynamic discovery of all ALB/NLB resources

Certificate domain/SAN matching

Clean, human‑friendly certificate reporting

Drift detection for all LB components

Manual review mode for ambiguous cases

Safe apply mode (no changes unless explicitly requested)

Configurable behavior via JSON infofile

Supports cross‑region DR architectures

⚙️ Configuration File (elb_config.json)
The infofile controls behavior, not resource definitions.
The tool dynamically discovers all resources in both regions.

Example

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

🔧 Source / Target Blocks
Define:

AWS profile

Region

VPC ID

The tool discovers all resources in these regions automatically.

📜 Policy Block
Controls sync behavior:

Setting	Meaning
register_targets	Register missing targets in DR
create_missing_load_balancers	Create LBs missing in DR
create_missing_target_groups	Create TGs missing in DR
sync_load_balancer_attributes	Sync LB attributes
sync_target_group_attributes	Sync TG attributes
sync_target_group_settings	Sync health checks
sync_listener_rules	Sync listener rules
sync_listeners	Sync listeners
sync_tags	Sync tags
allow_extra_target_rules	Allow DR to have extra rules
skip_target_registration	Skip registering missing targets
allow_certificate_domain_match	Match certs by domain/SAN


🚀 Running the Script
The script is named elbv2_reconcile_engine.py.

The actual supported CLI flags (from argparse) are:


--info-file INFO_FILE   (required)
--dry-run | --report-only | --yes   (mutually exclusive)
--apply
--allow-legacy
--no-create-missing-tg
--no-create-missing-lb
--no-sync-tags
--no-sync-listener-rules
--skip-target-registration
--report-path REPORT_PATH
--report-dir REPORT_DIR
--rollback-dir ROLLBACK_DIR

🛡️ Modes of Operation
1. Audit Mode (Safe)
Performs a full comparison and prints a drift report.

python elbv2_reconcile_engine.py --info-file elb_config.json --dry-run
This is the correct replacement for the old --audit flag.

2. Apply Mode (Dangerous)
Applies changes to DR based on policy rules.

python elbv2_reconcile_engine.py --info-file elb_config.json --apply --yes
--apply enables the Apply Engine

--yes confirms changes

Without --yes, the tool stays in audit mode

3. Report‑Only Mode

python elbv2_reconcile_engine.py --info-file elb_config.json --report-only
Generates a report without drift logic.

📄 Example Output

Listener: 443/HTTPS
  Action: UPDATE
  Drift:
    - Certificates differ
  Notes:
    - No DR ACM certificate match for source certificate api.example.com
    - Certificate ARN: arn:aws:acm:us-west-2:123:certificate/abcd1234

🔍 How It Works
1. World State Discovery
Loads all ALBs/NLBs, listeners, listener rules, target groups, certificates, attributes, and tags from both regions.

2. Match Context
Builds deterministic source → target mappings using:

ARN matching

Name matching

Certificate domain/SAN matching

Policy rules

3. Audit Engine
Detects:

Missing resources

Drift

Extra DR resources

Manual review cases

Produces recommended actions:

* CREATE
* UPDATE
* DELETE
* SKIP

MANUAL_REVIEW

4. Apply Engine (Optional)
Runs only when:

--apply --yes

It:

Creates missing resources

Updates drifted resources

Syncs listeners, rules, TGs, attributes, tags

Honors all policy settings

🧭 Manual Review
Some cases require human judgment:

Certificate domain mismatch

Ambiguous listener rule conditions

Conflicting TG settings

Unsafe deletes

These appear as:

Action: MANUAL_REVIEW
📌 Quick Reference
Task	Command
Audit (safe)	python elbv2_reconcile_engine.py --info-file elb_config.json --dry-run
Apply (dangerous)	python elbv2_reconcile_engine.py --info-file elb_config.json --apply --yes
Report only	python elbv2_reconcile_engine.py --info-file elb_config.json --report-only
Specify report directory	--report-dir ./reports
Specify rollback directory	--rollback-dir ./rollback
