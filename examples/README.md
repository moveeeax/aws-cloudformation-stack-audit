# Examples

## A clean stack

`clean-account/` holds one healthy stack: protected, drift-checked, deployed with a
service role, updated recently. It exits 0 and says so.

```
$ aws-cloudformation-stack-audit --from-files examples/clean-account
no findings across 1 stack(s)
$ echo $?
0
```

## A real account

`testdata/account/` is the fixture set the unit tests use, and it doubles as a tour of
every check:

```
$ aws-cloudformation-stack-audit --from-files testdata/account
SEVERITY  CHECK                      STACK            DETAIL
high      iam-wildcard               iam-bootstrap    AWS::IAM::ManagedPolicy BreakGlassPolicy looks like a blanket grant (...)
high      broken-state               legacy-rollback  UPDATE_ROLLBACK_FAILED: The following resource(s) failed to update: [MigrationQueue].
high      no-termination-protection  prod-db          termination protection off; owns AWS::RDS::DBInstance, AWS::S3::Bucket
...
```

## Collecting the dumps

`collect-dumps.sh` pulls `describe-stacks` plus a `describe-stack-resources` dump per
stack for one region:

```
$ ./examples/collect-dumps.sh eu-west-1 dumps/
wrote dumps to dumps/
$ aws-cloudformation-stack-audit --from-files dumps/ --fail-on high
```

Drift results are a separate call, because detection is asynchronous:

```
$ id=$(aws cloudformation detect-stack-drift --stack-name prod-db \
    --query StackDriftDetectionId --output text)
$ aws cloudformation describe-stack-drift-detection-status \
    --stack-drift-detection-id "$id" > dumps/prod-db-drift.json
```

An explicit drift dump wins over the `DriftInformation` summary inside
`describe-stacks`, which is often stale.
