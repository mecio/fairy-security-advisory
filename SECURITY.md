# Security policy

## Reporting a vulnerability

Please do not disclose a suspected vulnerability in a public GitHub issue,
discussion, pull request, screenshot, or advisory report.

Send a concise report to **gucw@proton.me** with:

- the affected fAIry Security Advisory version;
- the operating system and relevant installation details;
- reproducible steps or a minimal proof of concept;
- the expected and observed behavior;
- the potential impact;
- any suggested mitigation, if known.

Do not include credentials, access tokens, private source code, customer data,
or unredacted local configuration. If sensitive supporting material is needed,
first ask how it should be transferred.

Receipt will be acknowledged on a best-effort basis. After validation, the
maintainer will coordinate remediation and responsible disclosure. No response
or remediation deadline is guaranteed.

## Supported versions

Security fixes are normally applied to the latest published release. Older
versions may be asked to upgrade before a report is investigated further.

## Scope

Reports about fAIry's source code, desktop application, configuration handling,
backup/import validation, report processing, or AI CLI integration are in
scope. Vulnerabilities in third-party advisory services, Codex, Claude Code,
OSV-Scanner, Trivy, operating systems, or scanned projects should be reported
to their respective maintainers unless fAIry introduces the vulnerability.

Security advisory results produced by fAIry are not vulnerability reports
against fAIry itself. Use the normal follow-up workflow for those findings.
