"""Packaging regression tests for the VaultKnox wheel (Issue #10).

PR #13 (4287375) fixed wheels to ship ``vaultknox/_hermes_plugin/plugin.yaml``
but landed with no test: the wheel was verified manually once and CI never
repeated it. These tests build the wheel the same way the release workflow
does (``python -m build``: sdist first, then the wheel built from that
sdist) and assert the plugin manifest is inside the built artifact and
parses.

Re-derived from the preserved commit d5df43a (read as reference, not
cherry-picked): d5df43a inspected ``pyproject.toml`` package-data globs
instead of the artifact. This version checks the built wheel, so it
catches the manifest going missing whatever the packaging cause. One
config-level test is kept from that approach as well: the isolated build
environment installs setuptools 84.x, which copies package-dir data
files into the sdist even without a package-data entry, so the artifact
tests alone cannot go red when the PR #13 line is removed — the config
test is what makes this file mutation-sensitive to the exact Issue #10
regression.
"""

from __future__ import annotations

import fnmatch
import pathlib
import subprocess
import sys
import tomllib
import zipfile

import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE_MANIFEST = REPO_ROOT / "src" / "vaultknox" / "_hermes_plugin" / "plugin.yaml"
WHEEL_MANIFEST = "vaultknox/_hermes_plugin/plugin.yaml"


def test_source_plugin_manifest_exists_and_parses() -> None:
    """The manifest must exist in the source tree and parse to a non-empty mapping."""
    assert SOURCE_MANIFEST.is_file(), f"{SOURCE_MANIFEST} is missing from the source tree"
    data = yaml.safe_load(SOURCE_MANIFEST.read_text())
    assert isinstance(data, dict) and data, "plugin.yaml does not parse to a non-empty mapping"


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """Build the wheel once, exactly the way the release workflow does.

    ``python -m build`` (no ``--wheel``) builds the sdist first and then the
    wheel from a fresh sdist unpack in a temp dir, so a stale ``build/``
    directory in the repo tree cannot leak old files into the artifact.
    """
    out_dir = tmp_path_factory.mktemp("wheel")
    proc = subprocess.run(
        [sys.executable, "-m", "build", "--outdir", str(out_dir), str(REPO_ROOT)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"build failed:\n{proc.stdout}\n{proc.stderr}"
    wheels = sorted(out_dir.glob("*.whl"))
    assert len(wheels) == 1, f"expected exactly one wheel in {out_dir}, got {wheels}"
    return wheels[0]


def test_wheel_contains_plugin_manifest(built_wheel: pathlib.Path) -> None:
    """The built wheel must ship the plugin manifest (Issue #10)."""
    with zipfile.ZipFile(built_wheel) as zf:
        names = zf.namelist()
    assert WHEEL_MANIFEST in names, (
        f"{WHEEL_MANIFEST} is missing from {built_wheel.name} — hermes-vault install-hooks "
        f"fails with 'Packaged plugin file missing' on pip-installed vaultknox (Issue #10)"
    )


def test_wheel_plugin_manifest_parses(built_wheel: pathlib.Path) -> None:
    """The manifest shipped in the wheel must load as a non-empty mapping."""
    with zipfile.ZipFile(built_wheel) as zf:
        if WHEEL_MANIFEST not in zf.namelist():
            pytest.fail(f"{WHEEL_MANIFEST} is missing from {built_wheel.name}")
        data = yaml.safe_load(zf.read(WHEEL_MANIFEST))
    assert isinstance(data, dict) and data, "shipped plugin.yaml does not parse to a non-empty mapping"


def test_plugin_yaml_is_listed_in_package_data() -> None:
    """package-data must still declare the plugin manifest (PR #13's one-line fix).

    setuptools >= 84 copies package-dir data files into the sdist even
    without this entry, so the built-wheel tests above stay green when the
    line is deleted. This test is the one that goes red for exactly that
    deletion — the mutation that originally shipped broken wheels. Globs
    that still cover the manifest (e.g. ``_hermes_plugin/*.yaml``) pass;
    only losing coverage entirely fails.
    """
    config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    entries = config["tool"]["setuptools"]["package-data"]["vaultknox"]
    plugin_globs = [e for e in entries if "_hermes_plugin" in e]
    assert plugin_globs, (
        f"package-data {entries!r} has no _hermes_plugin entry — the declared "
        f"inclusion of the plugin manifest is gone (Issue #10, PR #13)"
    )
    assert any(fnmatch.fnmatch("plugin.yaml", g.rsplit("/", 1)[-1]) for g in plugin_globs), (
        f"package-data globs {plugin_globs!r} do not cover _hermes_plugin/plugin.yaml "
        f"— the wheel declaration for the plugin manifest is broken (Issue #10)"
    )
