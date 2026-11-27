# aws-cloudformation-stack-audit

[![ci](https://github.com/moveeeax/aws-cloudformation-stack-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-cloudformation-stack-audit/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.22%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Ranks a CloudFormation account by risk from saved `describe-*` JSON: stacks stuck in
`UPDATE_ROLLBACK_FAILED`, production stacks with termination protection off, drifted and
never-drift-checked stacks, stacks nobody has touched in years, and stacks that deploy
with the caller's permissions instead of a service role.

The console shows one stack at a time, which is why nobody audits this. One command over
a directory of dumps does.

## Install

```
go install github.com/moveeeax/aws-cloudformation-stack-audit/cmd/aws-cloudformation-stack-audit@latest
```

Or build from a checkout:

```
go build -o aws-cloudformation-stack-audit ./cmd/aws-cloudformation-stack-audit
```

## How it works

Everything is offline. You collect the dumps once, the tool reads them, and no AWS
credentials ever touch the audit — which is also why the whole test suite runs on
fixtures in CI.

Three dump shapes are recognised by their top-level key, so you don't have to label
files:

| Dump | Top-level key | Used for |
| --- | --- | --- |
| `describe-stacks` | `Stacks` | state, termination protection, `RoleARN`, age, inline drift |
| `describe-stack-resources` | `StackResources` | which stacks own stateful or IAM resources |
| `describe-stack-drift-detection-status` | `StackDriftDetectionId` | authoritative drift status and drifted-resource count |

Stack names are matched across dumps directly and through the name embedded in a stack
ARN, so `describe-stack-resources` output from a different call still lines up. Duplicate
stacks across dumps are deduplicated by stack id, and `DELETE_COMPLETE` stacks are
skipped entirely.

### Checks

| Check | Severity | Fires when |
| --- | --- | --- |
| `broken-state` | high | `CREATE_FAILED`, `ROLLBACK_FAILED`, `UPDATE_ROLLBACK_FAILED`, `UPDATE_FAILED`, `DELETE_FAILED`, `IMPORT_ROLLBACK_FAILED` |
| `no-termination-protection` | high | protection off **and** a resource dump shows RDS, S3, DynamoDB, EFS, VPC, EBS, FSx, Redshift, DocDB, ElastiCache or OpenSearch |
| `iam-wildcard` | high | an IAM resource whose name looks like a blanket grant (`AdministratorAccess`, `PowerUserAccess`, `FullAccess`, `Admin`, `*`) |
| `never-deployed` | medium | `REVIEW_IN_PROGRESS`: a change set was created and never executed |
| `no-stack-role` | medium | no `RoleARN`, so updates run with whatever the caller has |
| `drifted` | medium | drift detection reported `DRIFTED` |
| `abandoned` | low | healthy stack last changed more than `--max-age-days` ago |
| `drift-not-checked` | low | drift status is `NOT_CHECKED`, `UNKNOWN` or absent |

Findings carry a `remedy` where there is an obvious one-liner — the
`continue-update-rollback` or `update-termination-protection` call you were going to look
up anyway. It shows up in `--json`.

## Usage

```
aws cloudformation describe-stacks > dumps/stacks.json
aws cloudformation describe-stack-resources --stack-name prod-db > dumps/prod-db-resources.json
```

```
$ aws-cloudformation-stack-audit --from-files dumps/ --max-age-days 365
SEVERITY  CHECK                      STACK            DETAIL
high      iam-wildcard               iam-bootstrap    AWS::IAM::ManagedPolicy BreakGlassPolicy looks like a blanket grant (arn:aws:iam::123456789012:policy/AdministratorAccessCopy)
high      broken-state               legacy-rollback  UPDATE_ROLLBACK_FAILED: The following resource(s) failed to update: [MigrationQueue].
high      no-termination-protection  prod-db          termination protection off; owns AWS::RDS::DBInstance, AWS::S3::Bucket
medium    never-deployed             changeset-only   REVIEW_IN_PROGRESS: a change set was created but never executed
medium    no-stack-role              legacy-rollback  no service role: updates run with whatever permissions the caller has
medium    drifted                    prod-db          drift detection reported DRIFTED (3 drifted resources)
low       abandoned                  lambda-api       last changed 500 days ago (2025-07-15)
low       drift-not-checked          legacy-rollback  drift was never checked, so the stack's real state is unknown

10 finding(s) across 6 stack(s): 3 high, 4 medium, 3 low
```

`--from-files` takes a directory (every `*.json` in it) or a comma-separated list of
files. More, in a CI gate:

```
aws-cloudformation-stack-audit --from-files dumps/ \
  --only broken-state,no-termination-protection \
  --ignore-stack '^sandbox-' \
  --fail-on high --json
```

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--from-files` | — | directory of dumps, or a comma-separated file list (required) |
| `--max-age-days` | `365` | age above which a healthy stack counts as abandoned |
| `--only` | all | comma-separated check ids to run |
| `--ignore-stack` | — | regexp; matching stack names are skipped by every check |
| `--fail-on` | `high` | lowest severity that turns the exit code into 1 |
| `--json` | off | one JSON object per finding, in an array |
| `--version` | — | print the version |

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | no findings at or above `--fail-on` |
| 1 | findings at or above `--fail-on` |
| 2 | usage or input error |

So a nightly job is just the command — a non-zero exit is the alert.

## A note on the two heuristic checks

`no-termination-protection` only fires when a resource dump proves the stack owns
something unrecoverable. Without that dump it stays silent rather than flagging every
unprotected stack in the account, so collect the resource dumps if you care about this
check (`examples/collect-dumps.sh` does it in a loop).

`iam-wildcard` is a name heuristic and nothing more. `describe-stack-resources` returns
resource types and ids, never policy documents, so a role called `AdminHelper` is flagged
and a quietly over-permissive policy named `app-runtime` is not. Treat it as a pointer
at stacks worth opening, not as a policy analyser.

## Development

```
go vet ./...
go test ./...
```

Fixtures live in `testdata/account/`; `internal/audit` is tested entirely against them,
and the CLI's exit codes are tested through `run()`. Adding a check means adding a
fixture — `TestEveryCheckIDIsReachable` fails if a documented check has nothing that
triggers it.

## License

MIT. See [LICENSE](LICENSE).
