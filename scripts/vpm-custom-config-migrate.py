#!/usr/bin/env python3
"""Run the reviewed VPM custom-proxy migration helper on its target host."""

import argparse
import json
from pathlib import Path
import sys

from cryptolabs_proxy.migration import PROXY_READY_TIMEOUT, CustomConfigMigrator, MigrationError


def parser():
    command = argparse.ArgumentParser(description="VPM custom proxy migration (no default apply)")
    command.add_argument("--config-dir", type=Path, default=Path("/etc/cryptolabs-proxy"))
    command.add_argument("--backup-root", type=Path, default=Path("/etc/cryptolabs-proxy/migrations"))
    command.add_argument("--transport-timeout", type=int, default=15, help="per Docker/HTTP transport timeout in seconds")
    command.add_argument(
        "--readiness-timeout",
        type=int,
        default=PROXY_READY_TIMEOUT,
        help="Docker health and local auth readiness deadline in seconds",
    )
    subcommands = command.add_subparsers(dest="action", required=True)

    plan = subcommands.add_parser("plan", help="read-only sanitized migration plan")
    plan.add_argument("--container", default="cryptolabs-proxy")
    plan.add_argument("--proxy-image", required=True)

    apply = subcommands.add_parser("apply", help="explicit proxy-only switch with rollback")
    apply.add_argument("--container", default="cryptolabs-proxy")
    apply.add_argument("--proxy-image", required=True)
    apply.add_argument("--migration-id", required=True)
    apply.add_argument("--enable-vpm", action="store_true", help="write the canonical VPM registry entry and route")

    rollback = subcommands.add_parser("rollback", help="restore only the named proxy migration")
    rollback.add_argument("--container", default="cryptolabs-proxy")
    rollback.add_argument("--migration-id", required=True)
    return command


def main():
    args = parser().parse_args()
    migrator = CustomConfigMigrator(
        args.config_dir,
        args.backup_root,
        timeout=args.transport_timeout,
        readiness_timeout=args.readiness_timeout,
    )
    try:
        if args.action == "plan":
            print(json.dumps(migrator.plan(args.container, args.proxy_image).sanitized_manifest(), sort_keys=True))
        elif args.action == "apply":
            outcome = migrator.apply(args.container, args.proxy_image, args.migration_id, args.enable_vpm)
            print(json.dumps({"migration_id": args.migration_id, "state": outcome.state, "detail": outcome.detail}))
            if outcome.state == "candidate_retained":
                # The candidate is serving, but its fallback did not meet the
                # required health contract. Surface that operator action is
                # required without letting generic exception cleanup rewrite
                # the live managed configuration.
                return 2
        else:
            outcome = migrator.rollback(args.container, args.migration_id)
            print(json.dumps({"migration_id": args.migration_id, "state": outcome.state, "detail": outcome.detail}))
    except MigrationError as error:
        print(f"migration failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
