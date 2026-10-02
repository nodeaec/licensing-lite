# Key rotation: N/N+1 anchor

> Context: the Lite library verifies the Ed25519 lease against `TrustedAnchors[]`
> (public SPKI keys compiled into the code). The **Ed25519 private key lives on
> the server** — this doc covers rotating it and the strong-name `.snk`.

## Lease Ed25519 (trust anchor)

The `TrustedAnchors` array accepts **N and N+1 simultaneously** — that is what
lets you rotate the key without breaking already-installed plugins.

Steps (in this order — skipping the order breaks clients):

1. **Generate the new pair outside the repo** (server/HSM, never commit):
   the private key signs new leases; the public key (base64 SPKI) goes into the code.
2. **Publish Lite with `TrustedAnchors = [new, old]`**
   (minor/preview bump). A lease signed by either key passes.
3. **The server switches to signing everything with the new key.** Wait out the
   expiry window of old leases (`exp` ≤ 30d) plus a plugin-update margin.
4. **Publish the next Lite with `TrustedAnchors = [new]`** (removes the old one).
5. **Plugins update** (`dotnet add package NodeAec.Licensing.Lite` +
   rebuild + redeploy). Anyone who does not update after step 4 rejects new
   leases — which is why step 3 has a window.

Emergency (private key leaked / suspected): run 1–3 immediately
(same day), 4–5 in the next release. The Connector heartbeat
(`POST /license/validate`) plus a short `exp` limit the abuse window.

## Strong-name (.snk)

Changing the `.snk` changes the `PublicKeyToken` = **breaking change**: every plugin
must rebuild against the new package. Procedure:

1. Generate a new `.snk` (`sn.exe -k`), update `NODEAEC_SNK_BASE64`.
2. Publish a new Lite major/preview signed with the new key.
3. Plugins update the `PackageReference` and republish.
4. Revoke/delete the old key from the vault.

## Release checklist with rotation

- [ ] `TrustedAnchors` contains exactly the intended keys (new+old or new only)
- [ ] `sn -T` / reflection confirms the expected `PublicKeyToken`
- [ ] `.nupkg` + `.sha256` regenerated **after** Authenticode
- [ ] Matrix test: new-key lease accepted, removed-key lease rejected
