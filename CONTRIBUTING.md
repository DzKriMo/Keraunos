# Contributing

## Workflow

1. Create a branch from `main`.
2. Make focused changes with tests.
3. Run:
   - `py -3 -m pytest -q`
4. Open a PR with:
   - clear summary
   - risk notes
   - test evidence

## Code Standards

- Keep changes small and reviewable.
- Add tests for behavior changes.
- Avoid hardcoding secrets.
- Preserve policy and scope controls for pentesting actions.

## PR Checklist

- [ ] Tests added/updated
- [ ] README/docs updated
- [ ] No sensitive data committed
- [ ] Backward compatibility considered
