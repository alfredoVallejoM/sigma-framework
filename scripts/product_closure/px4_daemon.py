"""Compatibility wrapper for the packaged PX4 sigma-gateway CLI."""

from sigma.gateway.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
