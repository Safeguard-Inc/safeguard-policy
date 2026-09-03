## What and why

<!-- What does this change, and why does it exist? Keep it focused; the
commit messages should tell the same story at finer granularity. -->

## Checklist

- [ ] `./scripts/ci.sh` passes locally (rust + schema gates)
- [ ] Behavior changes ship with tests (core unit tests, contract integration
      tests, or schema negative/parity cases as appropriate)
- [ ] Policy/schema changes update the compatibility notes in
      `policy-schema/README.md`
- [ ] Rule semantics changes update `docs/rule-engine.md` (precedence must
      stay unambiguous)
- [ ] User-visible changes update `CHANGELOG.md`

## Security review

<!-- Answer the four questions from docs/threat-model.md: does this change
(1) make any path silently approve when information is missing, (2) allow
policy or registry state to mutate without admin/authority auth, (3)
introduce nondeterminism or external calls into evaluation, or (4) weaken
the append-only version model? If yes, flag for security review. -->

- [ ] No security-model impact (see docs/threat-model.md)

## Test plan

<!-- How was this verified? Reference the specific tests run. -->