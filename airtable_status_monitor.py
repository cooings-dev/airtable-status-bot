#!/usr/bin/env python3
"""
Airtable status monitor for cloud scheduling.

Modes:
- hourly-probe: check status once (no Slack), update down_active flag
- down-probe: if down_active is true, check status and post Slack every run while DOWN
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request

try:
    import certifi
except ImportError:  # pragma: no cover
    certifi = None

STATUS_URL = "https://status.airtable.com/api/v2/status.json"
UNRESOLVED_INCIDENTS_URL = "https://status.airtable.com/api/v2/incidents/unresolved.json"
SOURCE_URL = "https://status.airtable.com/"
DEFAULT_STATE_FILE = Path(".state/airtable_status_state.json")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_ssl_context() -> ssl.SSLContext:
    if certifi is not None:
        return ssl.create_default_context(cafile=certifi.where())
    return ssl.create_default_context()


def fetch_json(url: str, timeout_seconds: int) -> dict[str, Any]:
    req = request.Request(
        url=url,
        headers={"Accept": "application/json", "User-Agent": "airtable-status-bot/1.0"},
    )
    with request.urlopen(req, timeout=timeout_seconds, context=build_ssl_context()) as resp:
        body = resp.read().decode("utf-8")
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError(f"Unexpected response shape from {url}")
    return data


def collect_snapshot_or_error(timeout_seconds: int) -> dict[str, Any]:
    try:
        status_data = fetch_json(STATUS_URL, timeout_seconds)
        incidents_data = fetch_json(UNRESOLVED_INCIDENTS_URL, timeout_seconds)

        incidents = []
        for incident in incidents_data.get("incidents", []):
            if not isinstance(incident, dict):
                continue
            incidents.append(
                {
                    "name": incident.get("name", "Unnamed incident"),
                    "status": incident.get("status", "unknown"),
                    "impact": incident.get("impact", "unknown"),
                    "shortlink": incident.get("shortlink"),
                }
            )

        return {
            "kind": "status",
            "checked_at_utc": utc_now_iso(),
            "indicator": status_data.get("status", {}).get("indicator", "unknown"),
            "description": status_data.get("status", {}).get("description", "Unknown"),
            "incidents": incidents,
        }
    except (ValueError, json.JSONDecodeError, error.URLError, TimeoutError) as exc:
        return {
            "kind": "error",
            "checked_at_utc": utc_now_iso(),
            "error": f"{type(exc).__name__}: {exc}",
        }


def indicator_to_up_down(indicator: str) -> str:
    return "UP" if indicator == "none" else "DOWN"


def load_state(state_file: Path) -> dict[str, Any]:
    if not state_file.exists():
        return {"down_active": False}
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"down_active": False}


def save_state(state_file: Path, state: dict[str, Any]) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def build_down_payload(snapshot: dict[str, Any], max_incidents: int) -> dict[str, Any]:
    indicator = str(snapshot.get("indicator", "unknown"))
    description = str(snapshot.get("description", "Unknown"))
    incidents = snapshot.get("incidents", [])
    if not isinstance(incidents, list):
        incidents = []

    lines = [
        ":rotating_light: *Airtable is DOWN*",
        f"*Statuspage indicator:* `{indicator}`",
        f"*Description:* {description}",
        f"*Unresolved incidents:* {len(incidents)}",
    ]

    if incidents:
        lines.append("*Top unresolved incidents:*")
        for incident in incidents[:max_incidents]:
            line = (
                f"- {incident.get('name', 'Unnamed incident')} "
                f"(`impact={incident.get('impact', 'unknown')}`, "
                f"`status={incident.get('status', 'unknown')}`)"
            )
            shortlink = incident.get("shortlink")
            if shortlink:
                line += f" <{shortlink}|details>"
            lines.append(line)

    lines.append(f"*Checked at (UTC):* {snapshot.get('checked_at_utc', utc_now_iso())}")
    lines.append(f"*Source:* <{SOURCE_URL}|status.airtable.com>")

    return {
        "text": "Airtable is DOWN",
        "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}}],
    }


def send_slack(webhook_url: str, payload: dict[str, Any], timeout_seconds: int) -> None:
    req = request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=timeout_seconds, context=build_ssl_context()) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        if resp.status >= 300:
            raise RuntimeError(f"Slack webhook returned HTTP {resp.status}: {body}")


def run_hourly_probe(state_file: Path, timeout_seconds: int) -> int:
    state = load_state(state_file)
    snapshot = collect_snapshot_or_error(timeout_seconds=timeout_seconds)

    state["last_hourly_checked_at_utc"] = snapshot.get("checked_at_utc", utc_now_iso())
    state["last_kind"] = snapshot.get("kind")

    if snapshot.get("kind") == "status":
        indicator = str(snapshot.get("indicator", "unknown"))
        up_down = indicator_to_up_down(indicator)

        state["last_indicator"] = indicator
        state["last_description"] = snapshot.get("description")
        state.pop("last_error", None)
        state["down_active"] = up_down == "DOWN"

        if up_down == "DOWN":
            print("hourly probe: Airtable is DOWN, enabled down alerts")
        else:
            print("hourly probe: Airtable is UP, no Slack notification")
    else:
        state["last_error"] = snapshot.get("error")
        print(f"hourly probe failed: {snapshot.get('error')}")

    save_state(state_file, state)
    return 0


def run_down_probe(
    webhook_url: str,
    state_file: Path,
    timeout_seconds: int,
    max_incidents: int,
    dry_run: bool,
) -> int:
    state = load_state(state_file)
    if not state.get("down_active", False):
        print("down probe: inactive (UP mode), skipped")
        return 0

    if not dry_run and not webhook_url.strip():
        print(
            "Missing Slack webhook URL for down-probe. Set SLACK_WEBHOOK_URL or --webhook-url.",
            file=sys.stderr,
        )
        return 2

    snapshot = collect_snapshot_or_error(timeout_seconds=timeout_seconds)
    state["last_down_probe_checked_at_utc"] = snapshot.get("checked_at_utc", utc_now_iso())
    state["last_kind"] = snapshot.get("kind")

    if snapshot.get("kind") != "status":
        state["last_error"] = snapshot.get("error")
        save_state(state_file, state)
        print("down probe failed to fetch status, will retry next run")
        return 0

    indicator = str(snapshot.get("indicator", "unknown"))
    up_down = indicator_to_up_down(indicator)
    state["last_indicator"] = indicator
    state["last_description"] = snapshot.get("description")
    state.pop("last_error", None)

    if up_down == "DOWN":
        payload = build_down_payload(snapshot, max_incidents=max_incidents)
        if dry_run:
            print(json.dumps(payload, indent=2))
            print("dry-run: skipped Slack send")
        else:
            send_slack(webhook_url, payload, timeout_seconds=timeout_seconds)
            print("down probe: sent Slack notification")
        # Keep down_active=true; no additional state fields updated to avoid noisy commits.
        save_state(state_file, state)
        return 0

    state["down_active"] = False
    save_state(state_file, state)
    print("down probe: Airtable is UP, disabled down alerts")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Monitor Airtable status with split hourly/down schedule."
    )
    parser.add_argument(
        "--mode",
        choices=("hourly-probe", "down-probe"),
        required=True,
        help="hourly-probe = check only; down-probe = send Slack only while down_active=true.",
    )
    parser.add_argument(
        "--webhook-url",
        default="",
        help="Slack incoming webhook URL. Optional when down-probe is inactive.",
    )
    parser.add_argument(
        "--state-file",
        default=str(DEFAULT_STATE_FILE),
        help=f"Path to persisted state file. Default: {DEFAULT_STATE_FILE}",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=20,
        help="HTTP timeout in seconds.",
    )
    parser.add_argument(
        "--max-incidents",
        type=int,
        default=3,
        help="Maximum incident items included in Slack message.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print payload and skip Slack send.",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    state_file = Path(args.state_file).expanduser().resolve()

    if args.max_incidents < 0:
        print("--max-incidents must be >= 0", file=sys.stderr)
        return 2

    webhook_url = args.webhook_url.strip()

    if args.mode == "hourly-probe":
        return run_hourly_probe(
            state_file=state_file,
            timeout_seconds=args.timeout_seconds,
        )

    return run_down_probe(
        webhook_url=webhook_url,
        state_file=state_file,
        timeout_seconds=args.timeout_seconds,
        max_incidents=args.max_incidents,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
