# Evaluation Results

Generated evaluation output is written here by the control-plane evaluation runner.

The first baseline intentionally distinguishes between:

- **control-plane executable** cases,
- **model-dependent** cases,
- **not-yet-executable** cases.

A NOT RUN case is a coverage gap, not a pass.

Run locally with:

```text
python -m evaluations.run_control_plane_eval --check
```

The GitHub Actions workflow also uploads the generated JSON and Markdown baseline as an artifact.
