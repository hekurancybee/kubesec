# ICU.systems / KubeSec — Roadmap to Production-Grade

This document captures the key concerns, inconsistencies, and product/engineering roadmap items identified during a review of this repository.

The intent is to:
- converge the architecture into a coherent production design
- harden the agent/eBPF pipeline for reliability and portability
- define a safe, operable enforcement lifecycle (training → audit → enforcing)
- build a dashboard/workflow that makes enforcement usable in real organizations

---

## 0) Product Direction (confirmed)

- **Commercial, in-cluster platform only** (no SaaS, no outbound dependency)
- Agent runs as a privileged **DaemonSet** on every node
- **Dashboard runs in-cluster** (UI + API), protected via Kubernetes RBAC
- ClickHouse runs **in-cluster** as a single instance (dev) or a **multi-replica cluster** (production)
- **Runtime enforcement is local and in-memory**; ClickHouse is used for audit/persistence/analytics only
- Future modules may include **XDP firewall / network correlation**

---

## 0.1 Current Snapshot (What exists today)

### What works end-to-end (MVP tracer)
- eBPF syscall tracing via `raw_tracepoint/sys_enter`
- per-cgroup filtering in kernel (`target_cgroups` map)
- ring buffer event transport to Go userspace
- Kubernetes best-effort pod/container resolution (API cache + `/proc/<pid>/cgroup` parsing)
- optional ClickHouse event storage with aggressive deduplication

**Primary code paths**
- Kernel: `bpf/syscall_tracer.bpf.c`
- Userspace eBPF wrapper: `pkg/ebpf/tracer.go`
- Agent: `cmd/agent/main.go`
- K8s resolver: `pkg/resolver/k8s.go`
- ClickHouse store: `pkg/store/clickhouse.go`

### What exists but is not integrated into the agent
- Policy manager (K8s informer-based): `pkg/policy/manager.go`
- Annotation parsing and mode calculation: `pkg/policy/config.go`
- Local allowlist manager: `pkg/policy/allowlist.go`
- ClickHouse-backed workload state store: `pkg/store/workloads.go`

---

## 1) Architecture/Design Inconsistencies to Resolve

### 1.1 Enforcement “source of truth” mismatch
- `docs/ARCHITECTURE.md` emphasizes **local enforcement** and **ClickHouse for audit only**.
- `pkg/store/workloads.go` states ClickHouse is the “SINGLE SOURCE OF TRUTH for enforcement decisions”.
- `pkg/policy/allowlist.go` states **enforcement decisions are made locally** and never depend on DB queries.

**Decision required:** pick and document a single truth model.

Recommended production model:
- **Local enforcement is the only runtime dependency** (hot path must not depend on network/DB).
- ClickHouse is used for **audit + analytics + persistence/hydration**, but agent must operate safely if ClickHouse is down.

Deliverables:
- update `docs/ARCHITECTURE.md` and reconcile comments in `pkg/store/workloads.go`.
- define one canonical “Policy State Machine” section (see §4).

### 1.2 Policy system not wired into the agent
`cmd/agent/main.go` currently:
- discovers cgroups
- prints events
- optionally writes to ClickHouse
- has a demo “blocking” flag (`--block-syscall`) implemented as `bpf_send_signal(9)`

But it does not:
- watch annotations
- maintain allowlists per workload version
- perform per-event allow/deny decisions

Deliverables:
- integrate policy pipeline into `cmd/agent/main.go` (or a new `cmd/agentv2`/refactor) so the architecture matches docs.

### 1.3 Enforcement semantics: killing != blocking
Current “block” behavior:
- `bpf_send_signal(9)` on `sys_enter` (tracepoint)

Concerns:
- SIGKILL is disruptive and is not equivalent to “deny syscall with errno”.
- tracepoints are observation-oriented; deterministic allow/deny generally needs LSM or seccomp.

Decision required:
- enforcement mechanism roadmap: **Seccomp**, **eBPF LSM**, or **hybrid**.

---

## 2) Product Positioning / Market Readiness Concerns

### 2.1 Competitive differentiation required
The market exists (K8s runtime security), but “we trace syscalls” is not enough to win vs:
- Falco/Sysdig
- Aqua/Prisma/Wiz/Datadog
- Tetragon/Cilium

Differentiation candidates:
- version-aware behavior baselining tied to rollouts
- excellent operational UX (training status, approvals, diffs, rollbacks)
- “EDR-style” response workflow (triage, exceptions, audit trail)
- optionally: seccomp profile generation/export and/or LSM enforcement

### 2.2 Operational safety is the gating factor
Production blockers are mostly about:
- false positives
- insufficient training coverage
- environment drift
- safe rollout and “break-glass” workflows

This roadmap focuses heavily on those controls.

---

## 3) Engineering Hardening (Production-Grade Baseline)

### 3.1 Build portability
Issues:
- hard-coded libbpf include path in `Makefile` and `pkg/ebpf/tracer.go` go:generate flags.

Deliverables:
- make libbpf include path configurable via env var (e.g., `LIBBPF_HEADERS`) with a sane default.
- document build prerequisites and supported architectures.

### 3.2 Code hygiene and correctness
Issues noticed:
- duplicate `defer tracer.Close()` in `cmd/agent/main.go`.

Deliverables:
- clean up duplicate defers and add basic linting.

### 3.3 Observability
Deliverables:
- structured logging (log levels, JSON optional)
- agent metrics (Prometheus):
  - events/sec
  - ringbuf drops
  - per-workload unique syscall counts
  - enforcement decisions (allow/log/block)
  - resolver hit rate

### 3.4 Performance controls
Deliverables:
- configurable sampling / rate-limits for high-volume workloads
- ensure hot path is O(1) and lock-minimized
- ringbuf sizing & drop reporting

### 3.5 Kubernetes correctness
Deliverables:
- RBAC manifests for resolver/policy manager
- clarify node-level scope (DaemonSet) and host mounts

---

## 4) Policy Lifecycle: Training → Audit → Enforcing (Safe-by-Default)

### 4.1 Core principle
Blocking in production must be survivable. The system should never require humans to be perfect.

### 4.2 Fixed training duration alone is insufficient
Even for one “release”:
- rare code paths might not run in training
- cron/renewals may occur outside training window
- incident/debug workflows may require syscalls not seen in training

### 4.3 Recommended model: hybrid training (minimum time + convergence gates)
Keep current annotation style (simple), but make promotion smarter.

Suggested annotations (example):
- `icu.systems/secure: "true"`
- `icu.systems/training-min: "24h"` (or reuse `training-period` as min)
- `icu.systems/training-max: "7d"`
- `icu.systems/converge-window: "2h"`
- `icu.systems/converge-threshold: "0"` (or small number)
- `icu.systems/post-training-mode: "audit" | "enforcing"`

Promotion rule:
- train for at least `training-min`
- if new unique syscalls/hour <= threshold for `converge-window`, training completes
- if not stable by `training-max`, complete to **audit** (not enforcing) and require approval to enforce

### 4.4 Approval-based promotion (recommended for enterprise)
Default safe workflow:
1) training
2) audit (smoke test)
3) enforcing (manual approval)

This can be made automatic in low-risk environments later.

### 4.5 Version identity
Workload identity should include:
- kind/namespace/name
- rollout version (pod-template-hash)
- optionally: image digest
- optionally: arch/kernel family

Rationale: syscall sets can drift across kernel/arch.

### 4.6 Break-glass and rollback
Deliverables:
- one-click “disable enforcement” (per workload, per namespace)
- fast rollback to previous known-good allowlist
- “temporary allow” TTL exceptions (e.g., allow syscall X for 1h)

---

## 5) Enforcement Mechanism Roadmap (How to actually deny)

### 5.1 Options

#### Option A: Seccomp enforcement (fastest to production)
Pros:
- standard Kubernetes control
- deterministic ERRNO/KILL/LOG semantics
- portable, auditable, GitOps-friendly

Cons:
- limited expressiveness (no deep k8s context)
- shares kernel/seccomp attack surface (though this is true for most kernel features)

#### Option B: eBPF LSM enforcement (ICU-native independent layer)
Pros:
- in-kernel allow/deny and error returns
- dynamic policies possible
- aligns with “independent runtime EDR-like enforcement” goal

Cons:
- kernel compatibility/LSM requirements
- higher operational risk if not gated carefully
- verifier/kernel stability concerns must be addressed explicitly

#### Option C: Hybrid
- learn via eBPF
- enforce initially via seccomp (safe)
- optionally enable LSM enforcement for advanced customers

### 5.2 Recommended sequencing
1) ship audit + training + dashboard first
2) add “policy materialization” outputs:
   - seccomp profile generation/export
3) add LSM enforcement behind feature flag with strong safety controls

---

## 6) Dashboard / UX Roadmap (What “good dashboard” means)

### 6.1 The dashboard is a workflow tool, not just charts
Required screens:
- Workloads list (secure status, mode, training progress)
- Workload details:
  - current version identity (template hash)
  - allowlist size
  - “new syscalls last 1h/6h/24h”
  - violations timeline
  - profile diff vs previous version
- Approvals:
  - pending promotions to enforcing
  - pending syscall additions/removals
- Audit trail:
  - who approved what and when

### 6.2 Key operations
- Promote mode: training → audit → enforcing
- Add exception syscall (temporary/permanent)
- Roll back to prior profile
- Export policy (seccomp / policy bundle)

### 6.3 Integrations
- Slack/PagerDuty alerts for violations
- SIEM export (optional)
- GitOps sync (optional): export profiles to repo

---

## 7) Data & Storage Roadmap

### 7.1 ClickHouse usage
Keep ClickHouse as:
- audit events
- analytics (profiles, diffs)
- optional persistence/hydration (agent restart)

But runtime enforcement must be possible when ClickHouse is unavailable.

### 7.2 Schema considerations
- current dedup key in `pkg/store/clickhouse.go` is `namespace/pod/container/syscall`
  - good for “unique syscalls per pod”, but not enough for per-version allowlists

Deliverables:
- store workload identity fields explicitly:
  - kind/name/namespace
  - pod-template-hash
  - image digest
  - node/arch/kernel
- separate “events” from “profiles/allowlists” tables

---

## 8) Security Model & Threat Considerations

### 8.1 Trust boundaries / failure modes
Deliverables:
- formalize failure mode: open vs closed
- define how agent behaves if:
  - ClickHouse unavailable (continue enforce; degrade persistence/analytics)
  - dashboard unavailable (continue enforce; degrade UX/approvals)
  - K8s API unavailable (continue enforce with cached state; refresh later)
  - resolver fails (continue enforce at workload/cgroup scope; degrade metadata)

### 8.2 eBPF risk story
If positioning as an “independent layer”:
- document kernel requirements, verifier constraints, and supported hook types (tracepoint vs LSM)
- publish a compatibility matrix (kernel versions, distros, container runtimes)
- communicate defense-in-depth (not “invulnerable”)

### 8.3 Licensing security considerations
- store keys as Secrets (not ConfigMaps)
- enforce RBAC on license operations in the dashboard
- no outbound calls required for enforcement or continued operation
- expiry behavior should be safe-by-default (recommended: downgrade to audit-only)

---

## 9) Concrete Milestones (Suggested Phases)

### Phase 0 — Packaging & Operations (required for commercial)
- Helm chart(s): agent DaemonSet, dashboard Deployment, ClickHouse cluster (StatefulSet)
- upgrade/rollback strategy (versioned CRDs if needed)
- resource sizing guidance + recommended retention tiers
- backup/restore runbook (ClickHouse)
- support bundle: export diagnostics (agent logs, config, schema versions)

### Phase 0.1 — Licensing (in-cluster)
- license key stored as Kubernetes Secret mounted into agent/dashboard
- hot reload (watch Secret) without restart
- expiry behavior: degrade to **audit-only** (no breaking outages)
- audit trail for license events (who/when)

### Phase 1 — “Production Observability” (no blocking)
- stable event pipeline
- ClickHouse audit storage
- dashboard shows workloads + syscall discovery
- policy manager wired for annotations, but only controls training/audit state

Success criteria:
- low overhead on nodes
- reliable pod resolution
- actionable dashboards/queries

### Phase 2 — “Managed Training + Audit”
- per-workload version identity
- training completion rules (min duration + convergence)
- audit violations + alerting + review flow

Success criteria:
- minimal false positives in audit
- clear promotion workflow

### Phase 3 — “Enforcement v1”
- choose enforcement mechanism:
  - seccomp generation + apply OR
  - LSM enforcement behind feature flag
- break-glass, rollback, temporary exceptions

Success criteria:
- safe enforcement with rollback
- customers can adopt incrementally

### Phase 4 — “EDR-like Response & Enterprise Features”
- response actions (kill/scale/isolate)
- multi-cluster view
- RBAC in dashboard
- compliance reports

---

## Appendix A — Repo Items to Review/Update
- `cmd/agent/main.go`: integrate policy pipeline; remove duplicate `defer`.
- `pkg/policy/*`: decide canonical lifecycle; ensure post-training mode supports audit/enforcing.
- `pkg/store/workloads.go`: reconcile “source of truth” comment with chosen architecture.
- `Makefile` + `pkg/ebpf/tracer.go`: remove hard-coded libbpf path.
- `docs/ARCHITECTURE.md`: update to match implementation decisions.
