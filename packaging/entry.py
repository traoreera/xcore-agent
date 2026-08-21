"""
PyInstaller entry point.

Must import xcore_agent.cli with an absolute import — running
xcore_agent/cli.py directly as the PyInstaller script would make it the
top-level module, breaking its internal `from .agent...` relative imports.
"""

from xcore_agent.cli import app

if __name__ == "__main__":
    app()
