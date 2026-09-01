"""Local entry point for the intentionally vulnerable training lab.

The Flask debugger stays disabled unless LAB_DEBUG is explicitly enabled so the
lab's deliberate application vulnerabilities do not also expose Werkzeug's
interactive debugger when the container binds to 0.0.0.0.
"""
import os

from app import create_app


def _env_flag(name: str) -> bool:
    """Return True only for explicit truthy environment values."""
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


app = create_app()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("LAB_HOST", "127.0.0.1"),
        port=5000,
        debug=_env_flag("LAB_DEBUG"),
    )
