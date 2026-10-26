# Contributing

Thanks for helping. The most useful contributions are small and concrete.

## Report a wrong finding

If a check flags something that's actually fine, or misses something risky, open a **Bug report** with a config that reproduces it. Remove real keys and passwords first.

## Add a check

Each check needs:

- a function in [`checks.py`](ai_gateway_audit/checks.py) registered with `@check('GWA-NN')`, returning findings that name the setting, never its value;
- an entry in [`controls.yaml`](ai_gateway_audit/controls.yaml) with `needs:` and its framework mappings;
- tests for the passing and failing case, and a link to the gateway documentation for the setting in the pull request.

## Code changes

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pytest -q
```

If your change alters the report, regenerate the sample: `SOURCE_DATE_EPOCH=1791763200 python -m ai_gateway_audit demo --out sample-output`. CI fails if `sample-output/` is stale.

Security issues: please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
