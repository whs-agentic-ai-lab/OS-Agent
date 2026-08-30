# OS Agent live validation summary

## Scope

- Repository/branch: `whs-agentic-ai-lab/OS-Agent` / `not-verified-tool`
- AWS account/region: `078716600800` / `us-east-1`
- OS validation EC2: `i-0beb0f3a6f91673af`
- Other-team resources modified: **no**

## Tool inventory and live result

The `ToolDefinition` declarations under `backend/runtime_agent/tools` are the inventory source of truth. The r48 image regenerated the static inventory as **129 Tools / 383 Actions**.

Live serial run `tool-validation-3bc32759b2a2` finished with:

| Result | Actions |
|---|---:|
| PASS | 378 |
| FAIL | 0 |
| UNSUPPORTED_ENV | 3 |
| INCONCLUSIVE | 2 |
| Untested | 0 |
| Total | 383 |

`UNSUPPORTED_ENV`:

- `memory.lock.hugepage`
- `namespace.handle.bind_mount`
- `power.manage.suspend_probe`

`INCONCLUSIVE`:

- `journal.manage.rotate_probe`
- `journal.manage.vacuum_probe`

Both journal handlers and verifiers passed, but exact same-instance journal restoration cannot be proven. Their official resetters and the final full reset completed. The failure-only selector now includes only handler/verifier/resetter/timeout failures and excludes limitations.

Evidence root: `/var/lib/os-agent/validation-evidence/run-r3`

- Validated tool image: `tool-validation-6c72a31-r45`
- Validated digest: `sha256:de40c307b18defb084caa7baee3f34ca6c327adbcc8df7f229bab9369162d0c6`
- Tool source hash: `sha256:42c76ab03421f7ff79b9e992bbc2b59e9ea2f290882b0c0b87c77d6b5eb14246`

## Agent exposure

Agent model/runtime exposure is fail-closed. It exposes only the intersection of live `PASS` Actions and implemented production adapters: **22 Actions across 6 Tools**. The remaining **356 live-PASS Actions are not exposed**, because they do not yet have a production Agent resource mapping/runtime adapter.

## Autonomous attack and reset validation

Run `os-c40075777dd3` completed all **8/8 Trust Boundaries**. Every boundary reached `MAX_IMPACT_VERIFIED`, completed search, and completed verified rollback with verdict `BROKEN / L4_RESTORED`.

- Contract: `contract-os-c40075777dd3`
- Frozen steps: 3
- Chain hash: `sha256:154e81286c89ce992bc089aaa49384b1263ec38ee3fcc3e925e16d2b01fcb3e6`
- Permission minimization: completed, 20 trials, at least one minimal set verified
- Full reset: verified for permissions, sessions, run directories, fixtures, and target containers
- C1/C2/C3 health: healthy
- Profile hash before/after reset: `sha256:d160c43b49750d469dce0688d1f17f6e94ca06ba4eb94f58aeed6b06edbf2451`
- Official environment verifier: passed

Remote evidence:

- `/var/lib/os-agent/validation-evidence/agent-runs/os-c40075777dd3-before-reset.json`
- `/var/lib/os-agent/validation-evidence/agent-runs/os-c40075777dd3-full-reset.json`
- `/var/lib/os-agent/validation-evidence/agent-runs/os-c40075777dd3-environment-verify.txt`
- `/var/lib/os-agent/validation-evidence/agent-runs/os-c40075777dd3-after-reset.json`

## Deployment and verification

- Runtime image: `tool-validation-6c72a31-r48`
- Runtime digest: `sha256:d0e12e55f119b6433a43fafe4a8982b6681f898f69bb16779e6be9d5ea669752`
- Tests: targeted `57 passed`; full non-root `322 passed, 2 skipped`; root Supervisor `1 passed`
- Terraform: `fmt -check -recursive` passed; `validate` passed
- Terraform plan: `25 add / 0 change / 0 destroy`, using a local backend without imported remote state; plan only, not applied
