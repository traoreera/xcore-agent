"""Guards against circular-import regressions that a normal pytest run can
mask: pytest's own test collection imports modules in whatever order the
test files happen to reach them, so a cycle that only bites when a
specific module is imported FIRST (before anything else has initialized
its dependencies) can pass a full suite run yet still break a real,
narrower entry point (a script doing `import xcore_agent.plugin_resolver`
directly, a docs tool, ...).

Each module here is imported in its own fresh subprocess — the only way to
guarantee nothing else has already populated sys.modules first — with no
other xcore_agent import preceding it.
"""

import subprocess
import sys

import pytest

# `plugin_resolver` is top-level but reaches into `agent.marketplace_client`
# (a submodule of the `agent` package) — importing it FIRST, before
# anything has triggered `agent/__init__.py`'s own import chain (which
# pulls in `.pipeline`, which imports `plugin_resolver` right back), used
# to raise ImportError. Only ever avoided in practice because `xcore_agent.
# cli`'s own import order happened to initialize `agent` first — see
# plugin_resolver.py's TYPE_CHECKING-guarded import for the actual fix.
MODULES_IMPORTABLE_STANDALONE = [
    "xcore_agent.plugin_resolver",
    "xcore_agent.resolve_sources",
    "xcore_agent.cli",
    "xcore_agent.agent.marketplace_client",
    "xcore_agent.agent.pipeline",
    "xcore_agent.agent.marketplace_pipeline",
    "xcore_agent.packer.builder",
]


@pytest.mark.parametrize("module", MODULES_IMPORTABLE_STANDALONE)
def test_module_importable_as_the_first_xcore_agent_import(module):
    result = subprocess.run(
        [sys.executable, "-c", f"import {module}"], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
