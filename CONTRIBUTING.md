# Contributing

Thank you for helping improve fAIry Security Advisory.

## Before opening an issue

- Search existing issues and documentation.
- Confirm the problem occurs with the latest published version.
- Remove local paths, credentials, tokens, private project names, inventories,
  security findings, and production information from examples and screenshots.
- Use `SECURITY.md` instead of a public issue for suspected vulnerabilities in
  fAIry itself.

## Development setup

Clone the repository and start the guided launcher:

```bash
./fairy-security-advisory
```

The launcher can create the isolated `.venv` after confirmation. The optional
desktop dependencies are installed only when the GUI is requested.

## Making changes

- Keep scanned projects read-only.
- Preserve the factory/local configuration split: public defaults belong in
  `config/`, while machine-specific values belong in ignored `config/local/`.
- Keep environment-derived reports, conversations, backups, and inventories
  under ignored `output/` storage.
- Do not add credentials, private paths, real inventories, or production
  evidence to tests, documentation, screenshots, or fixtures.
- Prefer synthetic examples such as `DEMO-*`, `example.com`, and generic project
  names.
- Update README and the desktop user guide when behavior changes.
- Add or update tests for functional changes.

## Local verification

This project intentionally does not require a hosted CI service. Before a pull
request, run:

```bash
./fairy-security-advisory --action tests
./fairy-security-advisory --action validate
./fairy-security-advisory --action prepublish
```

The pre-publication source-reachability step requires network access. If it
cannot run, document that limitation in the pull request.

## Pull requests

Keep each pull request focused. Explain the user-visible outcome, relevant
safety considerations, tests performed, and any remaining limitation. Never
attach real ignored output or local configuration merely to demonstrate a
change.

By contributing, you agree that your contribution is licensed under
AGPL-3.0-or-later, the license of this project.
