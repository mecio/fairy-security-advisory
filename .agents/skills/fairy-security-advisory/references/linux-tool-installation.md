# Linux installation of OSV-Scanner and Trivy

Use this guide only when a scanner is unavailable. First run
`python3 scripts/validate_project.py --config-dir config`; the validator reads
`/etc/os-release` and displays the appropriate distribution block.

These commands are suggestions to display, not automatic authorization. Before
execution, verify the official documentation, distribution, version, and
architecture, then obtain an explicit user request.

## OSV-Scanner

Arch Linux:

```bash
sudo pacman -S osv-scanner
```

Alpine Linux:

```bash
sudo apk add osv-scanner
```

On Linux x86_64 and arm64, the desktop installer prefers the official
precompiled release. It downloads both the binary and the published checksum,
verifies SHA-256, and installs only for the current user under
`~/.local/bin/osv-scanner`. It does not require Go or administrator privileges.

For architectures without an official precompiled binary, a supported Go
toolchain may be used:

```bash
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
export PATH="$PATH:$(go env GOPATH)/bin"
```

Official container alternative:

```bash
docker pull ghcr.io/google/osv-scanner:latest
```

The application checks the installed Go version before enabling this fallback.
Verify the current Go requirement in the
[official OSV-Scanner documentation](https://google.github.io/osv-scanner/installation/).

## Trivy

For Debian and Ubuntu, use the official DEB repository:

```bash
sudo apt-get install -y wget gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install -y trivy
```

For RHEL, CentOS, and derivatives, use the official RPM repository shown by the
validator. For Arch Linux:

```bash
sudo pacman -S trivy
```

Official container alternative:

```bash
docker pull aquasec/trivy:latest
```

For other distributions, choose a verified release by following the
[official Trivy documentation](https://trivy.dev/docs/latest/getting-started/installation/).

## After installation

Verify without starting a scan:

```bash
osv-scanner --version
trivy --version
python3 scripts/validate_project.py --config-dir config
```
