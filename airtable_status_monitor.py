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
import os
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request
from zoneinfo import ZoneInfo

try:
    import certifi
except ImportError:  # pragma: no cover
    certifi = None

STATUS_URL = "https://status.airtable.com/api/v2/status.json"
UNRESOLVED_INCIDENTS_URL = "https://status.airtable.com/api/v2/incidents/unresolved.json"
SOURCE_URL = "https://status.airtable.com/"
DEFAULT_STATE_FILE = Path(".state/airtable_status_state.json")
PACIFIC_TZ = ZoneInfo("America/Los_Angeles")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc_iso(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def format_pt_label(checked_at_utc: str) -> str:
    try:
        dt_utc = parse_utc_iso(checked_at_utc)
    except ValueError:
        dt_utc = datetime.now(timezone.utc)
    dt_pt = dt_utc.astimezone(PACIFIC_TZ)
    return dt_pt.strftime("%Y-%m-%d %I:%M:%S %p PT")


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

    checked_pt = format_pt_label(str(snapshot.get("checked_at_utc", utc_now_iso())))
    lines.append(f"*Checked at (PT):* {checked_pt}")
    lines.append(f"*Source:* <{SOURCE_URL}|status.airtable.com>")

    return {
        "text": "Airtable is DOWN",
        "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}}],
    }


def build_recovered_payload(snapshot: dict[str, Any]) -> dict[str, Any]:
    indicator = str(snapshot.get("indicator", "unknown"))
    description = str(snapshot.get("description", "Unknown"))
    checked_pt = format_pt_label(str(snapshot.get("checked_at_utc", utc_now_iso())))

    lines = [
        ":white_check_mark: *Airtable is UP (Recovered)*",
        f"*Statuspage indicator:* `{indicator}`",
        f"*Description:* {description}",
        f"*Checked at (PT):* {checked_pt}",
        f"*Source:* <{SOURCE_URL}|status.airtable.com>",
    ]

    return {
        "text": "Airtable is UP (Recovered)",
        "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}}],
    }


def send_slack_webhook(webhook_url: str, payload: dict[str, Any], timeout_seconds: int) -> None:
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


def slack_api_call(
    method: str,
    bot_token: str,
    payload: dict[str, Any],
    timeout_seconds: int,
) -> dict[str, Any]:
    req = request.Request(
        f"https://slack.com/api/{method}",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {bot_token}",
        },
        method="POST",
    )
    with request.urlopen(req, timeout=timeout_seconds, context=build_ssl_context()) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        if resp.status >= 300:
            raise RuntimeError(f"Slack API HTTP {resp.status}: {body}")

    data = json.loads(body)
    if not isinstance(data, dict) or not data.get("ok", False):
        raise RuntimeError(f"Slack API {method} failed: {body}")
    return data


def post_slack_message(
    bot_token: str,
    channel_id: str,
    payload: dict[str, Any],
    timeout_seconds: int,
) -> str:
    data = slack_api_call(
        "chat.postMessage",
        bot_token=bot_token,
        payload={"channel": channel_id, **payload},
        timeout_seconds=timeout_seconds,
    )
    ts = data.get("ts")
    if not isinstance(ts, str) or not ts:
        raise RuntimeError(f"Slack API chat.postMessage missing ts: {json.dumps(data)}")
    return ts


def update_slack_message(
    bot_token: str,
    channel_id: str,
    ts: str,
    payload: dict[str, Any],
    timeout_seconds: int,
) -> None:
    slack_api_call(
        "chat.update",
        bot_token=bot_token,
        payload={"channel": channel_id, "ts": ts, **payload},
        timeout_seconds=timeout_seconds,
    )


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
    slack_bot_token: str,
    slack_channel_id: str,
    state_file: Path,
    timeout_seconds: int,
    max_incidents: int,
    dry_run: bool,
) -> int:
    state = load_state(state_file)
    if not state.get("down_active", False):
        print("down probe: inactive (UP mode), skipped")
        return 0

    use_chat_update = bool(slack_bot_token.strip() and slack_channel_id.strip())
    has_webhook = bool(webhook_url.strip())
    if not dry_run and not use_chat_update and not has_webhook:
        print(
            (
                "Missing Slack delivery config. Provide either: "
                "(SLACK_BOT_TOKEN + SLACK_CHANNEL_ID) for message updates, "
                "or SLACK_WEBHOOK_URL for append-only messages."
            ),
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
            if use_chat_update:
                last_ts = str(state.get("last_slack_message_ts", "")).strip()
                last_channel = str(state.get("last_slack_channel_id", "")).strip()
                try:
                    if last_ts and last_channel == slack_channel_id:
                        update_slack_message(
                            bot_token=slack_bot_token,
                            channel_id=slack_channel_id,
                            ts=last_ts,
                            payload=payload,
                            timeout_seconds=timeout_seconds,
                        )
                        print("down probe: updated existing Slack message")
                    else:
                        posted_ts = post_slack_message(
                            bot_token=slack_bot_token,
                            channel_id=slack_channel_id,
                            payload=payload,
                            timeout_seconds=timeout_seconds,
                        )
                        state["last_slack_message_ts"] = posted_ts
                        state["last_slack_channel_id"] = slack_channel_id
                        print("down probe: posted new Slack message")
                except Exception:
                    # If update path fails (deleted message, channel change, etc.),
                    # fallback to creating a new anchor message once.
                    posted_ts = post_slack_message(
                        bot_token=slack_bot_token,
                        channel_id=slack_channel_id,
                        payload=payload,
                        timeout_seconds=timeout_seconds,
                    )
                    state["last_slack_message_ts"] = posted_ts
                    state["last_slack_channel_id"] = slack_channel_id
                    print("down probe: posted new Slack message after update fallback")
            else:
                send_slack_webhook(webhook_url, payload, timeout_seconds=timeout_seconds)
                print("down probe: sent Slack notification")
        # Keep down_active=true; no additional state fields updated to avoid noisy commits.
        save_state(state_file, state)
        return 0

    state["down_active"] = False
    if use_chat_update and not dry_run:
        last_ts = str(state.get("last_slack_message_ts", "")).strip()
        last_channel = str(state.get("last_slack_channel_id", "")).strip()
        if last_ts and last_channel == slack_channel_id:
            recovered_payload = build_recovered_payload(snapshot)
            try:
                update_slack_message(
                    bot_token=slack_bot_token,
                    channel_id=slack_channel_id,
                    ts=last_ts,
                    payload=recovered_payload,
                    timeout_seconds=timeout_seconds,
                )
                print("down probe: updated existing Slack message to recovered")
            except Exception as exc:
                print(f"down probe: failed to update recovery message: {exc}", file=sys.stderr)
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
        default=os.getenv("SLACK_WEBHOOK_URL", ""),
        help="Slack incoming webhook URL. Optional when down-probe is inactive.",
    )
    parser.add_argument(
        "--slack-bot-token",
        default=os.getenv("SLACK_BOT_TOKEN", ""),
        help="Slack bot token (xoxb-...) for chat.postMessage/chat.update mode.",
    )
    parser.add_argument(
        "--slack-channel-id",
        default=os.getenv("SLACK_CHANNEL_ID", ""),
        help="Slack channel ID for message update mode (e.g., C12345678).",
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
        slack_bot_token=args.slack_bot_token.strip(),
        slack_channel_id=args.slack_channel_id.strip(),
        state_file=state_file,
        timeout_seconds=args.timeout_seconds,
        max_incidents=args.max_incidents,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
