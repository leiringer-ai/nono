---
nep: 0006
title: Dedicated credential ownership transfer
authors:
  - leiringer-ai (with Codex assistance)
status: draft
created: 2026-10-18
superseded-by:
---

# NEP-0006: Dedicated credential ownership transfer

## Summary

Propose an explicit, offline transfer of an existing dedicated Nono OAuth
account to a trusted local credential broker without another provider login.
The source must relinquish refresh authority before the destination becomes
active. This is a design review request, not an implemented or accepted protocol.

Tracking issue: [Nexus #80](https://github.com/leiringer-ai/nexus/issues/80).
The maintained fork has issues disabled; the linked issue records operator
authorization, agent disclosure, approach and risks. Review is requested against
this fork's `nexus` branch, not upstream `main`.

## Motivation

Nexus can already use broker-first Codex authorization through both its Nono
and MicroVM routes. Existing dedicated Nono-only authorizations still need a
supported migration. Repeating device login or copying a credential file into a
second independently refreshing owner does not satisfy that requirement.

Inspection at `7c1d56c7d804ad517725c08174673f4ccb9fc9c1` found OAuth capture
persistence in `crates/nono-proxy/src/oauth_capture/{mod,persist}.rs`, but no
supported transfer transaction or durable interprocess migration fence. This is
a missing lifecycle feature, not a claim of a demonstrated vulnerability. No
real credential store was read for this proposal.

### Goals

- Preserve a valid authorization from an explicitly selected dedicated store.
- Keep credential handling exclusively in the owning Nono process and broker.
- Prove at most one refresh authority across transfer, restart and recovery.
- Reject account conflicts without silently merging or replacing authorization.
- Provide redacted status and idempotent recovery for interrupted transfers.
- Qualify Linux and macOS separately before claiming support on either.

### Non-Goals

- Importing normal operator `.codex` or `.claude` homes.
- Giving Runtime controllers, execution clients or agents credential access.
- Cross-host synchronization, online transfer during active sessions, or generic
  credential export to files/stdout.
- Changes to sandbox grants, provider account policy or the `nono` library API.
- Claiming Claude live qualification without an available account.

## Proposal

This section defines proposed invariants and review decisions. Exact commands,
wire messages and storage schemas remain TBD until the design is accepted.

An explicit operator command in `nono-cli` would select a dedicated source and
approved destination. Credential mechanisms remain in the owning proxy/broker
components; the policy-free sandbox library gains no migration policy.

### Ownership transitions

| State | Source may refresh | Destination may refresh | Recovery constraint |
|-------|--------------------|-------------------------|---------------------|
| Source active | Yes | No | Existing operation |
| Source fenced | No | No | Keep source inaccessible to sessions; resume or safely abort |
| Destination staged | No | No | Encrypted, inactive staging tied to the same transaction |
| Source surrendered | No | No | Resume activation; never restore an old source snapshot |
| Destination active | No | Yes | Retry completion/cleanup, retain source tombstone |

1. Preflight checks the selected source, destination identity, account selection
   and conflicting destination accounts before changing authority. A different
   account or existing independent authorization is rejected; even matching
   account metadata does not prove the same refresh lineage. No implicit merge.
2. Quiesce every source OAuth user, including supervisors holding credentials in
   memory and refresh requests in flight. Acquire a durable, exclusive admission
   fence before staging. Failure to prove quiescence denies transfer.
3. Nono sends selected material directly to the authenticated broker over a
   narrowly scoped local channel. The broker durably encrypts inactive staging.
   Both owners bind the transaction to source identity, destination identity and
   the selected account. Runtime may observe redacted state only.
4. After verified durable staging, Nono durably surrenders refresh authority and
   makes the legacy source credential representation unusable. A persistent
   tombstone prevents compatible future Nono starts from reopening that account.
5. The broker verifies durable surrender and activates the staged account.
   Lost acknowledgements retry the same transaction. Cleanup never removes the
   only recovery record before the other owner durably knows the outcome.

An in-process mutex or a marker file that old versions ignore cannot establish
step 2 or step 4. Review must select a defensible method to exclude old running
owners and legacy starts. Removing a file cannot revoke a token already loaded
in another process. If those facts cannot be established for a source deployment,
transfer must report it unsupported without changing the working authorization.

### Recovery and rollback

Journal updates require explicit durability and ordering guarantees, including
file and directory synchronization where relevant. Missing, corrupt or divergent
records deny both activation and source reuse until owner-controlled recovery.
No timeout can infer that the other owner abandoned a transaction.

Before surrender, an abort may reactivate the source only after proving the
staged destination cannot activate now or later, including after restart. After
surrender, recovery moves forward to the same destination. Returning ownership
would require a separately reviewed transfer of the current credential lineage;
restoring a pre-transfer backup is not rollback. Unknown outcomes of in-flight
provider refresh must be resolved before fencing is considered complete.

### Compatibility and platform scope

Existing broker-first login remains unchanged. Dedicated Nono-only use remains
available until an operator explicitly selects a supported migration. No automatic
store scanning or conversion occurs. Supported source versions and minimum
migration-aware versions must be documented after the legacy-start question is
resolved; version checks alone are not enforcement.

Linux Landlock and macOS Seatbelt continue to restrict session processes. The
migration command is a trusted owner operation outside those processes, with no
new session grants. Linux cannot rely on deny-within-allow: source stores,
journals and transfer endpoints must remain outside every allowed session tree.
macOS denial rules do not replace owner authentication or durable fencing.
Peer authentication and encrypted storage availability must be tested separately
on each OS, including macOS Keychain/security-session behavior. Unsupported or
locked storage fails closed without plaintext fallback.

## Security Considerations

- **Least privilege:** only the explicit owning command and approved broker may
  exchange secrets. No generic export endpoint, child credential environment,
  CLI secret arguments, broad filesystem grant or additional agent network route.
- **Peer authentication:** same UID and a socket pathname alone do not establish
  the intended receiving owner. The design must bind both owners to the reviewed
  deployment and transaction with an authenticated bootstrap; the exact mechanism
  is TBD. A substituted same-user service must not receive credentials.
- **Path integrity:** validate component-based paths and ownership, reject
  symlinks where necessary, and bind operations to opened objects. Canonicalization
  alone does not prevent replacement races. Journal and socket directories need
  restricted permissions and identity checks through every state transition.
- **Secrecy:** secret material uses zeroizing buffers; serialization, errors,
  debug output, logs and audit records must not reveal tokens or login codes.
  Staging is encrypted at rest by the destination's storage authority. Account
  diagnostics and transaction identifiers must avoid unnecessary personal data.
- **Fail secure:** partial writes, unavailable keystores, wrong peers, unknown
  process ownership, replay, version mismatch and lost acknowledgements never
  authorize two refreshers. Availability may be lost pending recovery.
- **Trust scope:** this does not defend against a malicious host administrator or
  an operator deliberately restoring credential backups outside the supported
  lifecycle. It must prevent supported concurrent and accidental legacy launches
  from creating two owners. The exact enforceable legacy boundary is a review
  blocker, not an assumed guarantee.
- **Policy boundary:** account selection, destination admission and operator UX
  belong in `nono-cli`; the sandbox library's capabilities stay unchanged.

## Alternatives Considered

- **Broker-first login only:** already useful, but fails preservation of existing
  dedicated authorizations required by Nexus #80.
- **Repeat provider login:** simple but changes the accepted operator outcome.
- **Copy auth files or print an export:** creates uncontrolled credential copies
  and bypasses ownership and refresh coordination.
- **Let the controller migrate the store:** violates the credential boundary.
- **Leave Nono as the authority and broker through it:** potentially avoids
  surrender, but creates a durable owner/service dependency and a different
  shared lifecycle. Retain as a review alternative if safe transfer is infeasible.
- **Marker-only fencing:** insufficient for old processes or legacy binaries.

## Validation Required Before Qualification

Use synthetic credentials for fault injection and boundary tests before any
explicitly authorized live transfer. Cover both supported host platforms:

- Active supervisors, concurrent starts, legacy binaries, outstanding refresh
  requests and attempts to reuse an old source after activation.
- Failure before and after each durable write, process death, restart, corrupt
  journals, disk-full errors, acknowledgement loss, duplicate messages and replay.
- Account conflicts, same-account independent authorizations, repeated completion,
  pre-surrender abort, and refusal to restore stale post-surrender snapshots.
- Wrong peers, endpoint substitution, symlink/rename races, unsupported versions,
  unavailable keystores, and verification that diagnostics contain no secrets.
- A bounded real Codex transfer from a dedicated login, followed by renewal,
  broker restart, Nono and MicroVM execution, and independent session cleanup,
  without another device login. Claude account-dependent work stays separate.

The review must approve the invariants before implementation. A later test report
must identify the actual supported source versions and platforms; a synthetic
pass alone is not live qualification.

## Open Questions

- What mechanism proves all pre-existing source owners have stopped and prevents
  legacy starts from loading a usable credential throughout the transition?
- How are source and destination identities authenticated beyond UID/path checks,
  and what minimum trusted installation/bootstrap is required?
- How is surrender proven durably to the broker without granting it source-store
  read access? What recovery authority handles a missing or damaged journal?
- What provider metadata reliably establishes account identity without exposing
  tokens, and how are ambiguous refresh outcomes resolved?
- Which Linux and macOS keystore/security-session combinations are supportable?
- Does the maintained fork accept this direction or prefer retaining Nono as the
  permanent authority? Which maintainers must explicitly approve the credential
  boundary under the fork's inherited governance?

These are acceptance blockers. This draft neither assigns maintainer approval
nor authorizes implementation ahead of an accepted NEP.
