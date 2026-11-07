# Portainer authorized the wrong environment

**Two authenticated authorization bugs in Portainer CE. One root cause. A verified patch.**

*Reported privately to Portainer on 2026-11-05: [GHSA-x6pm-hvxv-g44v](https://github.com/portainer/portainer/security/advisories/GHSA-x6pm-hvxv-g44v).*

Portainer's security policy lists **environment access** among the controls it is responsible for
making work as documented: a user with access to Docker environment A is not supposed to read,
change, or deploy to environment B. The policy frames that responsibility around Business Edition
and separately commits to triaging reports from either edition, because both share the codebase —
that commitment is what makes a CE reproduction meaningful, and it is quoted below. Both bugs below break that boundary, and both come from the
same mistake. Vector 1 authorizes the source environment and never authorizes the destination at
all. Vector 2 authorizes the value it has just overwritten instead of the environment the stack
was stored on. In both cases the environment that is actually being attacked sits outside the
authorized decision.

| # | Endpoint | What a standard user can do |
|---|---|---|
| 1 | `POST /api/stacks/{id}/migrate` | run arbitrary containers on a Docker host they have no access to |
| 2 | `PUT /api/stacks/{id}?endpointId=` | take over and destroy another user's stack |

Tested on **Portainer CE 2.45.3** (`be20b574172a27251fd8648cefe1b810a8dad6a5`, 2026-10-16). The
same code is present on `develop` as of 2026-10-30. A patch is included at the end and was
verified A/B against the unpatched build.

One note on versions: the original reproduction ran the released `portainer/portainer-ce:2.45.3`
image, which reports `2.45.3`. The A/B below builds both binaries from the pinned source, which
declares `APIVersion = "2.45.0"` (`api/portainer.go:2126`) — so the source-built binaries report
`2.45.0` while containing the same code. Same tree, two builds, one patch between them.

---

## The control that is supposed to stop this

Portainer's object-level authorization runs through `AuthorizedEndpointOperation(r, endpoint)`
in `api/http/bouncer`. For a non-admin it checks that the user's team has an access policy on
that environment. Stack management is separately gated by
`AllowStackManagementForRegularUsers`, which defaults to `true` for a new environment
(`api/portainer.go:2787`).

The intended rule is simple:

> An object's stored environment is the authorization subject. A request-supplied environment
> may only be an additional target, and it must be authorized too.

Neither handler below follows it.

---

## Vector 1 — migrate deploys to an environment it never authorized

`api/http/handler/stacks/stack_migrate.go`

```go
endpoint, err := handler.DataStore.Endpoint().Endpoint(stack.EndpointID)   // source
...
if err := handler.requestBouncer.AuthorizedEndpointOperation(r, endpoint); err != nil {  // :84
    return httperror.Forbidden("Permission denied to access endpoint", err)
}
...
targetEndpoint, err := handler.DataStore.Endpoint().Endpoint(portainer.EndpointID(payload.EndpointID)) // :126
...
stack.EndpointID = portainer.EndpointID(payload.EndpointID)                // :133
...
migrationError := handler.migrateStack(r, stack, targetEndpoint)           // :153
```

The `POST /api/stacks/{id}/migrate` body carries `{"EndpointID": N}`. Line 84 authorizes the
stack's **current** environment. The destination is resolved at 126 and handed to `migrateStack`
at 153 without ever passing through `AuthorizedEndpointOperation`, `userCanManageStacks`, or a
resource-control lookup.

### Reproduced

Standard user `alice` has access to environment A and nothing else. Environment B is explicitly
configured with `AllowStackManagementForRegularUsers=false`.

| Step | Result |
|---|---|
| `GET /api/endpoints/2` (B) | **403** |
| `POST /api/stacks` on B | **403** — "Stack creation is disabled for non-admin users" |
| Docker proxy on B | **403** |
| `POST /api/stacks/1/migrate {"EndpointID":2}` | **200** |
| containers on B afterwards | **1** (`probe-a-p-1`, alice's compose project) |
| containers on A afterwards | **0** |

The three 403s are the point. Each tests one guard independently, and each says no. The attack
goes around all three, and the deployment lands on B with Portainer's own server-side Docker
credentials — the attacker never needs network access to B or its Docker socket.

The container is created from attacker-supplied compose content, using Portainer's own server-side
Docker credentials. That is arbitrary container deployment on the target host. Whether it escalates
to host compromise depends on that environment's Docker configuration — we did not demonstrate a
host escape and do not claim one.

---

## Vector 2 — update rewrites ownership, then checks it

`api/http/handler/stacks/stack_update.go`

```go
if endpointID != 0 && endpointID != stack.EndpointID {   // :169
    stack.EndpointID = endpointID                        // :170
}

endpoint, err := tx.Endpoint().Endpoint(stack.EndpointID)
...
if err := handler.requestBouncer.AuthorizedEndpointOperation(r, endpoint); err != nil {  // :180
    return nil, nil, nil, httperror.Forbidden("Permission denied to access environment", err)
}
...
resourceControl, err := tx.ResourceControl().ResourceControlByResourceIDAndType(
    stackutils.ResourceControlID(stack.EndpointID, stack.Name), portainer.StackResourceControl)  // :191
```

`endpointId` is a **mandatory** query parameter — the call is
`RetrieveNumericQueryParameter(r, "endpointId", false)`, where the third argument is `optional`, so
`false` means required. The handler writes it into `stack.EndpointID`
at line 170, then authorizes the environment it just wrote. The resource-control lookup at 191
is also keyed to the rewritten environment, so the victim's ownership restriction is never
consulted at all.

### Reproduced

`alice` has access to A. `bob` owns a stack on B. Alice also has a stack on A with the **same
name** as bob's — `shared` — and then sends `PUT /api/stacks/{bob's id}?endpointId=A` with her own
compose content.

The name collision is a real precondition, not a detail. Line 170 rewrites the stack's environment
to A; line 191 then looks up the resource control for `(A, "shared")`. Alice's own `shared` stack
on A supplies a matching resource control, so that check passes. Bob's resource control, keyed to
`(B, "shared")`, is never consulted.

| Probe | Result |
|---|---|
| alice reads bob's stack on B | **403** |
| alice updates it against its real environment | **403** |
| `endpointId=99999` | **404** — the parameter is used verbatim |
| `endpointId=A` (alice's own) | **200** |
| stack record afterwards | `EndpointId` 2 → 1, `CreatedBy: bob`, `UpdatedBy: alice` |
| bob's stack list | empty |
| alice reads the file | **200** |

Impact is takeover and destruction: the stack record moves to alice's environment, the compose
file on disk is replaced with her content, and the stored `Env` is replaced. What this does
**not** do is disclose bob's original content — the update overwrites it rather than returning
it. That distinction matters and should not be overstated.

---

## Why this is not "deployment hardening"

Portainer's security policy treats some outcomes as out of scope. Quoted verbatim from
`SECURITY.md` (retrieved 2026-11-05):

> An outcome that depends on the operator's network posture, on an optional control left at its
> default, or on a control that exists only in Business Edition is deployment hardening and is not
> treated as a vulnerability.

> Reports are triaged against this model regardless of the edition they were found in, since both
> editions share a codebase. A report that shows a Portainer control failing as documented is in
> scope.

The same section lists "authentication, authorization, environment access, resource ownership and
governance policies" as Portainer's responsibility. None of the exclusions apply:

1. `AuthorizedEndpointOperation` is not an optional control. It is the environment authorization
   control, and environment access is named in the policy as Portainer's responsibility.
2. Vector 1 works **against an explicitly hardened destination**:
   `AllowStackManagementForRegularUsers=false` is set on B and is bypassed.
3. The policy commits to triaging reports against this model regardless of edition, because both
   editions share a codebase.
4. The policy also notes that exposing CE on a network, or operating it with multiple users, is a
   deployer decision. That clause is about controls CE does not ship — it names the SSRF allow-list
   as the example. The control broken here is not one of those: it ships in CE, it is the same code
   in BE, and vector 1 defeats it even when the operator has explicitly hardened the destination
   with `AllowStackManagementForRegularUsers=false`.

This is a Portainer control failing as documented.

---

## The fix

`fix.patch` — two files, 105-line diff.

**`stack_migrate.go`**: authorize `targetEndpoint` and apply `userCanManageStacks` to it before
the stack record is rewritten or deployed.

**`stack_update.go`**: retrieve the security context first, authorize the environment **stored on
the stack**, key the resource-control lookup to that same environment, and make changing a
stack's environment admin-only (with both source and destination authorized). Legacy stacks with
`EndpointID == 0` keep the documented `endpointId` workaround: the parameter is authorized, then
persisted as the stack's environment.

### Verification

Same source tree, same build pipeline (Go 1.26, `CGO_ENABLED=0`, binary overlaid on the released
image). The patch is the only difference.

| | unpatched | patched |
|---|---|---|
| Vector 1 migrate | **200**, container on B | **403**, 0 containers on B |
| Vector 2 update | **200**, record moved | **403**, record unchanged |
| alice's own stack on A | works | still works, still running |

The patched migrate returns `403 Permission denied to access endpoint`; the patched update
returns `403` before the stack record is touched. The legitimate path is unaffected: alice can
still create and run a stack on her own environment.

Logs in `evidence/`: `repro-migrate.log`, `repro-migrate-unpatched.log`, `repro-update.log`,
`repro-update-unpatched.log`.

---

## Detection while unpatched

The relevant detail is in the request body (vector 1) and query string (vector 2), so the
reliable place to detect this is an HTTP-aware proxy in front of Portainer, not application logs
alone.

- `POST /api/stacks/{id}/migrate` by a non-admin where the destination environment in the body
  differs from the stack's current environment.
- `PUT /api/stacks/{id}?endpointId=` by a non-admin where the parameter differs from the stack's
  stored environment.
- Any stack whose `EndpointId` changes without an administrator acting, or whose `UpdatedBy` is
  not a member of the team that owns the destination environment.

Both rules need the stack's stored environment. A proxy that can query Portainer's API can join on
it; a cheaper approximation is to alert on any non-admin request to either endpoint and review.

## Containment while unpatched

- Apply the patch. Setting `AllowStackManagementForRegularUsers=false` on the destination does
  **not** stop vector 1 — that is the bypass.
- If you cannot patch: remove stack management from non-admin users entirely, or run separate
  Portainer instances per trust domain. Only give a user stack rights on environments where you
  would accept them deploying arbitrary containers.

---

## Limits

- Tested on CE only. BE shares this code path in the same files (no `go:build ee` tags), but was
  not executed here.
- The Kubernetes variant of vector 2 — where `stack_update.go:190` skips the resource-control
  block and `handler.go:141` returns true for non-Docker endpoints — was read, not executed.
- Three branches in the patch were compile-checked but not exercised by the repros: the
  `userCanManageStacks` check on the migrate destination, the admin-only move branch, and the legacy
  `EndpointID == 0` write-back. The repros cover the two non-admin attack paths. In the patched
  migrate run, alice fails the destination authorization before the manage-stack check is reached.
- No CVE has been assigned at the time of writing.

## On the timing

Portainer's policy asks reporters not to disclose until a fix has been released. We reported with a
24-hour notice and are publishing two days later, with no response from the maintainers. The bug is
reachable by any authenticated user who has stack rights on one environment, and the fix is in this
post. The policy sets no response SLA; waiting for a release would leave every multi-environment
installation exposed for an indefinite period while the patch that closes it is already written and
tested. The report was sent before this post went up, and this section will be updated with
Portainer's response.

## Timeline

- **2026-10-30** — reproduced on 2.45.3, gate and controls built.
- **2026-11-05** — reported privately to Portainer as
  [GHSA-x6pm-hvxv-g44v](https://github.com/portainer/portainer/security/advisories/GHSA-x6pm-hvxv-g44v),
  with a 24-hour publication notice.
- **2026-11-07** — published, after two days with no maintainer response.
- Fix status is updated at the top of this file as it changes.


---

## A note on the repro scripts

The two self-contained end-to-end scripts are not published here yet. They were included in the
private report and turn a valid non-admin account into container deployment on another
environment, so they stay private until a fixed release is available. Everything else needed to
verify the analysis — the vulnerable code paths, the control sets, the exact requests, the
transcripts, and a working patch — is in this repository.
