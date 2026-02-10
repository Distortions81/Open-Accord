# GoAccord Test Plan

Date: 2026-02-10
Scope: manual validation of current mesh, TUI client, channels, friends, and persistence behavior.

## Preconditions
- Build/test succeeds:
```bash
go test ./...
```
- Peer scripts are available under `scripts/`.

## Environment Setup
1. Start local mesh:
```bash
./scripts/reboot-peers.sh
./scripts/status-peers.sh
```
Expected: peers running, logs in `.run/peers/logs/`.

## TUI Basics
1. Startup
```bash
go run ./client-tui -addr 127.0.0.1:9101
go run ./client-tui -addr 127.0.0.1:9102
```
Expected: both connect and show `login_id`.

2. Direct send
- In A: `/to <login_id_B>` then type message.
Expected: B receives `deliver`.

3. Auto contacts and delete
- In A: `/to <login_id_B>` and send one message.
- In A: `/contacts`
Expected: alias for B exists.
- In A: `/remove-contact <alias>`
- In A: `/contacts`
Expected: alias removed.

## Friend Flow
1. Friend request
- In A: `/friend-add <login_id_B>` (or alias)
Expected: B sees `friend_request` notification.

2. Friend accept
- In B: `/friend-accept <login_id_A>`
Expected: both see `friend_update` indicating friendship.

## Channel Flow
1. Public channel create and invite by non-member
- In A: `/channel-create dev general public`
- In B (not member): `/group dev` and `/channel general`
- In B: `/invite <login_id_C>`
Expected: C sees invite (public allows anyone to invite anyone).

2. Join public channel without invite
- In C: `/channel-join dev general`
Expected: join succeeds (`channel_joined` notice).

3. Channel fanout
- In A: `/group dev` `/channel general`
- In A: `/channel-send hello-channel`
Expected: members receive `channel_deliver`.

4. Private channel invite restrictions
- In A: `/channel-create secret ops private`
- In C (not member): `/group secret` `/channel ops` `/invite <login_id_B>`
Expected: invite ignored/rejected (non-member private invite not allowed).

5. Private channel member invite with friend requirement
- In A: `/invite <login_id_B>` then B joins.
- In B: `/invite <login_id_C>` before friendship with C.
Expected: invite ignored/rejected.
- Make B and C friends (`/friend-add`, `/friend-accept`).
- In B: `/invite <login_id_C>` again.
Expected: invite accepted and C can join.

## Persistence Mode
1. Offline replay
```bash
go run ./server -listen :9201 -persistence-mode persist
```
Action:
- B logs in then disconnects.
- A sends direct message to B.
- B reconnects with same key.
Expected: message is replayed on reconnect.

2. Hosted gating
```bash
go run ./server -listen :9202 -persistence-mode persist -persist-auto-host=false
```
Action: login with new identity.
Expected: login rejected by hosted policy.

## Limits and Defensive Behavior
1. Oversized packet
- Send > `max-msg-bytes`.
Expected: dropped.

2. Burst rate
- Flood messages quickly.
Expected: drops after burst/rate thresholds.

3. Peer logs
- Inspect `.run/peers/logs/*.log`.
Expected: no repeated identity errors under normal run.

## Maintenance Rule
On protocol/behavior changes:
1. Update `PROTOCOL.md`.
2. Update `TEST_PLAN.md`.
3. Add/adjust automated tests.
