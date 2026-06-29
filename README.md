# Enterprise ELBv2 Reconciliation Engine vNext

This vNext diagnostic build is based on the last working v8 baseline, with two architectural fixes added:

1. **Listener rule discovery fix**
   - AWS `describe_rules` responses do not always include `ListenerArn` in each rule object.
   - Earlier builds required `ListenerArn` during normalization, which could cause all rules to be skipped.
   - vNext injects the parent listener ARN during rule normalization so rule counts and comparisons are valid.

2. **Name-tag-first subnet resolver**
   - Subnet auto-mapping now first matches normalized subnet `Name` tags.
   - Example:
     - `Prod-App-Private-A` -> `app-private-a`
     - `DR-App-Private-A` -> `app-private-a`
   - Public/private behavior and CIDR mask are then used as validation.
   - Generic scoring is now only a fallback.

## Safe discovery run

```bash
python elbv2_reconcile_engine_vnext.py \
  --info-file elbv2-config.vnext.example.json \
  --report-only \
  --allow-legacy \
  --debug-discovery
```

## Dry-run

```bash
python elbv2_reconcile_engine_vnext.py \
  --info-file elbv2-config.vnext.example.json \
  --dry-run \
  --allow-legacy \
  --debug-discovery
```

## What to verify first

The discovery diagnostics should show non-zero listener rule counts if Production has non-default listener rules.

Look for output like:

```text
Listener HTTPS:443
  Source rules: total=5, non_default=4, priorities=['default', '10', '20', '30', '40']
  Target rules: total=3, non_default=2, priorities=['default', '10', '20']
```

If source rules are visible, the rule discovery bug is fixed and we can proceed to rule parity updates.
