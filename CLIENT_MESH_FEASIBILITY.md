# Client-Participating Mesh Feasibility

Date: 2026-02-15
Status: Draft

## Goal
Evaluate whether Open Accord clients can become first-class mesh participants and help persist user/group/channel/profile state, instead of relying only on server persistence nodes.

## Short Answer
Yes, technically feasible, with major tradeoffs.

- Feasible for profile cards, group/channel metadata, and membership snapshots.
- Feasible for encrypted message blob replication if clients opt in.
- Harder for reliable delivery guarantees due to client churn, NAT, battery limits, and trust boundaries.
- Best result is likely a hybrid model: server peers remain backbone; clients are optional edge replicas/caches.

## Current Baseline
Today:
- Servers form the relay mesh.
- Persistence is optional and server-local (SQLite).
- Clients are authenticated endpoints, not routing/storage peers.

Implication:
- Control plane is simple and predictable.
- Data durability depends on persist-enabled servers, not user devices.

## What Could Move to Clients
### Good candidates
- Profile data (`profile_data`) cache/replication.
- Group/channel metadata (known groups/channels, invite history, membership snapshots).
- Encrypted DM envelopes as opaque blobs.
- Presence observations (short-lived only).

### Poor candidates
- Global authoritative membership truth without a conflict model.
- Strong offline delivery guarantees from only mobile/laptop peers.
- Abuse-control enforcement (rate limiting, bans) as a client responsibility.

## Feasibility by Dimension
### Networking
- LAN/public-IP desktops: reasonable peerability.
- Consumer NAT/mobile: low inbound reachability without relay assist.
- Conclusion: clients can dial out and sync, but cannot be assumed always reachable.

### Security/Trust
- Clients are less trusted operationally than managed servers.
- Malicious clients can serve stale or selective data.
- Mitigation: signatures on replicated records, hash chaining/sequence checks, multiple-source reconciliation.

### Consistency
- Multi-writer state (group membership, profile edits) needs conflict resolution.
- Feasible options:
  - per-record last-write-wins with signed timestamp/clock skew bounds;
  - per-object monotonic sequence signed by object owner;
  - CRDT-like merge for selected sets.
- Without this, client-side replication will diverge quickly.

### Storage and Cost
- Client disks can store substantial metadata cheaply.
- Need explicit limits:
  - max retention age;
  - max bytes per namespace (`user`, `group/channel`);
  - max replicated peers/sources.
- Opt-in policies are required for privacy and resource control.

### UX/Product
- Pros: better offline startup, faster local reads, resilience if one server is down.
- Cons: more local state complexity, sync delays, possible stale views.

## Required Protocol/Runtime Additions
Minimum additions:
1. Client peer role/capability (for example `role=client_peer`, capability flags).
2. Signed replication records with stable IDs and causal metadata.
3. Pull sync cursors (`since_seq` / `since_time`) per namespace.
4. Data scopes and ACL rules (what a client may request/serve).
5. Retention policy fields (TTL/size hints) to avoid unbounded growth.
6. Source ranking and reconciliation logic (prefer freshest valid signed state).

Operational additions:
- Background sync scheduler.
- Quotas and eviction.
- Corruption/staleness detection.
- Optional encryption-at-rest for replicated blobs.

## Risks
- Increased attack surface (Sybil-like replica peers, stale replay, selective withholding).
- Significant implementation complexity in clients.
- Harder debugging due to eventual consistency.
- More protocol surface area during prototype phase.

## Recommended Direction
Adopt a staged hybrid approach.

### Phase 1 (Low risk)
- Keep server mesh as authority for transport/routing.
- Add client-side replicated cache for:
  - profiles,
  - group/channel metadata,
  - encrypted DM envelopes (optional).
- Sync is pull-based from trusted servers/peers using cursors.

### Phase 2 (Medium risk)
- Allow desktop-class clients to serve cached records to other clients.
- Require signed records and multi-source validation.
- Keep write authority constrained (no broad ACL changes from replicas).

### Phase 3 (High risk, optional)
- Promote eligible clients to limited relay/storage peers.
- Introduce stronger trust scoring, anti-abuse controls, and auditability.

## Decision
Feasible and worthwhile if scoped as optional, cache-first replication.

Not recommended now:
- replacing server persistence with client-only durability.

Recommended now:
- design cursor-based sync and retention limits first;
- keep server nodes as backbone;
- let clients improve availability without becoming authority nodes.

## Open Questions
- What data classes are allowed for client replication by default?
- Do we require explicit user consent per data class?
- What is the conflict-resolution rule per replicated object type?
- Should mobile clients be replication consumers only, while desktops can be providers?
