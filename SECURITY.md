# Security Policy

## Reporting a Vulnerability

Safeguard is compliance infrastructure for Stellar Confidential Tokens:
a mistake here can freeze legitimate users or let sanctioned actors transact.
Please treat security findings with the seriousness they deserve.

**Do not open a public GitHub issue for a vulnerability.** Instead, report
privately so the issue can be fixed before it is disclosed.

Private reporting options:

- Open a [GitHub Security Advisory](https://github.com/Safeguard-Inc/safeguard-policy/security/advisories/new)
- Email the maintainers at the address listed in the repository metadata

Please include:

- The affected crate/module and version
- A description of the vulnerability and its impact
- Steps to reproduce, or a minimal proof of concept
- Any suggested fix, if known

## Scope

In scope:

- The Soroban contracts in `crates/safeguard-contract`
- The policy engine in `crates/safeguard-core`
- Policy schema and validation tooling
- Documentation that influences deployment decisions

Out of scope:

- Dependencies already fixed upstream (report those upstream)
- Third-party services used by example tooling

## Response times

| Severity | First response | Fix target |
| -------- | -------------- | ---------- |
| Critical | 24 hours       | 7 days      |
| High     | 3 days         | 14 days     |
| Medium   | 7 days         | 30 days     |
| Low      | 14 days        | 90 days     |

## Security model

Compliance enforcement must be **fail-closed** and **deterministic**. See
[`docs/security.md`](docs/security.md) and [`docs/threat-model.md`](docs/threat-model.md)
for the full model. Key rules:

- Policy state changes require an authorized admin or authority.
- Evaluations never depend on external network calls or nondeterministic state.
- When compliance-relevant information is missing, the configured action is
  conservative (never silently approve).
- Sanctions and identity data enter the chain only through reviewed adapters
  and deterministic registries.
