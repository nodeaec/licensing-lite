# AGENTS.md — NodeAec.Licensing.Lite

Instructions for coding agents working in **this repository**, the offline license gate
NuGet package. Agents adding licensing to a partner plugin do not work here: they follow
the [`licensing-integrate` skill](https://github.com/nodeaec/revit-sample-plugin/tree/main/.agents/skills/licensing-integrate)
in the Sample Plugin.

## Rules that never bend

- **Fail closed.** `Gate.Validate` never throws and never returns a licensed `Snapshot`
  unless the signature, the claims and the product all check out.
- **Additive only.** Never remove or change a public member, and never change or reuse a
  `GateReason` number: on Revit 2025+ one copy of Lite loads per Revit session, so plugins
  built against older versions run against this one.
- **No network, no UI, no background work.** The Connector writes the lease; Lite only reads
  and verifies it.
- **Signing.** Never publish an unsigned build. The strong-name key (`.snk`) never enters
  git and is never read or printed by an agent; `scripts/release.ps1` takes its path. CI never
  signs. Publishing to nuget.org (`dotnet nuget push`) is done by the maintainer, never by an
  agent. Details: `docs/signing.md`, `docs/rotation.md`.

## Build and test

```powershell
dotnet build src/NodeAec.Licensing.Lite/NodeAec.Licensing.Lite.csproj -c Release
dotnet test tests/NodeAec.Licensing.Lite.Tests/NodeAec.Licensing.Lite.Tests.csproj -c Release
```

## Facts that go stale, and where to check them

| Fact | Source of truth | Also written in |
|---|---|---|
| Package version | `<Version>` in `src/NodeAec.Licensing.Lite/NodeAec.Licensing.Lite.csproj` | `README.md` (install snippet, "Since" notes), and in other repos: the Connector, Sample Plugin and template csproj files and their docs |
| Published versions | <https://www.nuget.org/packages/NodeAec.Licensing.Lite> | |
| `Snapshot` members | `src/NodeAec.Licensing.Lite/Gate.cs` | `README.md` Snapshot table; revit-connector `docs/PARTNER_INTEGRATION.md`; revit-sample-plugin `API.md` §4 and the skill's `references/licensing-gate.md` |
| `GateReason` values and messages | `GateReason.cs`, `GateMessages.cs` | `README.md` reasons table; the partner guide's table; the sample's `API.md` §5 |
| Strong-name public key token | `docs/signing.md` | the sample's `API.md` §8.2 |
| Trust anchors | `Cryptography/LeaseSignatureVerifier.cs` | `docs/rotation.md` |

After a change, find every repeat: `grep -rn "<old value>" .` here, and tell the user which
other repos repeat it (column 3), since a release here usually needs a Connector release that
references it first, then the sample and the template.
