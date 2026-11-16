#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Local, provider-neutral accounting for AI commands launched by fAIry."""

from __future__ import annotations

import datetime as dt
import json
import os
import selectors
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent.parent
USAGE_FILE = ROOT / "output/ai-usage/events.jsonl"


def _number(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def usage_from_event(provider: str, event: dict[str, Any]) -> dict[str, int | float]:
    """Normalize the documented JSON result fields emitted by supported CLIs."""
    usage = event.get("usage")
    if not isinstance(usage, dict):
        usage = {}
    result: dict[str, int | float] = {
        "input_tokens": _number(usage.get("input_tokens")),
        "output_tokens": _number(usage.get("output_tokens")),
        "cached_input_tokens": _number(
            usage.get("cached_input_tokens", usage.get("cache_read_input_tokens"))
        ),
        "cache_creation_input_tokens": _number(usage.get("cache_creation_input_tokens")),
    }
    if provider == "claude" and isinstance(event.get("total_cost_usd"), (int, float)):
        result["cost_usd"] = float(event["total_cost_usd"])
    return result


def _visible_event_text(provider: str, event: dict[str, Any]) -> str:
    if provider == "codex" and event.get("type") == "item.completed":
        item = event.get("item")
        if isinstance(item, dict) and item.get("type") == "agent_message":
            return str(item.get("text", ""))
    if provider == "claude" and event.get("type") == "result":
        return str(event.get("result", ""))
    return ""


def append_usage_record(record: dict[str, Any], path: Path = USAGE_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    payload = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def append_cli_diagnostic(path: Path, provider: str, message: str) -> None:
    """Retain concise CLI errors in the private run event log."""
    cleaned = message.strip()
    if not cleaned:
        return
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    line = f"{dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')} CLI {provider}: {cleaned[:4000]}\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, line.encode("utf-8"))
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def run_tracked_command(
    command: list[str], provider: str, *, model: str, profile: str, execution_mode: str,
    capture_path: Path | None = None, event_log_path: Path | None = None,
) -> int:
    """Stream a structured CLI run while retaining only aggregate local usage."""
    started = time.monotonic()
    totals: dict[str, int | float] = {
        "input_tokens": 0, "output_tokens": 0, "cached_input_tokens": 0,
        "cache_creation_input_tokens": 0, "cost_usd": 0.0,
    }
    visible_messages: list[str] = []
    process = subprocess.Popen(
        command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
        bufsize=1,
    )
    assert process.stdout is not None
    for line in process.stdout:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            print(line, end="", flush=True)
            if event_log_path is not None:
                append_cli_diagnostic(event_log_path, provider, line)
            continue
        if not isinstance(event, dict):
            continue
        if event_log_path is not None and str(event.get("type", "")).casefold() in {
            "error", "failed", "failure",
        }:
            detail = event.get("message") or event.get("error") or event
            append_cli_diagnostic(event_log_path, provider, str(detail))
        usage = usage_from_event(provider, event)
        # Final result events contain cumulative totals, so retain the maximum
        # rather than summing repeated snapshots.
        for key, value in usage.items():
            totals[key] = max(totals.get(key, 0), value)
        visible = _visible_event_text(provider, event)
        if visible:
            visible_messages.append(visible)
            print(visible, flush=True)
    exit_code = process.wait()
    if capture_path is not None and exit_code == 0:
        capture_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        capture_path.parent.chmod(0o700)
        temporary = capture_path.with_name(f".{capture_path.name}.{os.getpid()}.tmp")
        try:
            temporary.write_text("\n\n".join(visible_messages).strip() + "\n", encoding="utf-8")
            temporary.chmod(0o600)
            os.replace(temporary, capture_path)
            capture_path.chmod(0o600)
        finally:
            temporary.unlink(missing_ok=True)
    append_usage_record({
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "provider": provider,
        "model": model,
        "profile": profile,
        "execution_mode": execution_mode,
        "duration_seconds": round(time.monotonic() - started, 2),
        "exit_code": exit_code,
        **totals,
    })
    return exit_code


def load_usage_records(path: Path = USAGE_FILE) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def summarize_usage(provider: str, records: Iterable[dict[str, Any]] | None = None) -> dict[str, Any]:
    selected = [
        record for record in (records if records is not None else load_usage_records())
        if record.get("provider") == provider
    ]
    return {
        "runs": len(selected),
        "successful_runs": sum(record.get("exit_code") == 0 for record in selected),
        "input_tokens": sum(_number(record.get("input_tokens")) for record in selected),
        "output_tokens": sum(_number(record.get("output_tokens")) for record in selected),
        "cached_input_tokens": sum(_number(record.get("cached_input_tokens")) for record in selected),
        "cost_usd": sum(float(record.get("cost_usd") or 0) for record in selected),
    }


def codex_rate_limits(executable: str, timeout: float = 6.0) -> dict[str, Any] | None:
    """Read the authenticated Codex allowance through its local app-server API."""
    try:
        process = subprocess.Popen(
            [executable, "app-server", "--stdio"], cwd=ROOT,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
        )
    except OSError:
        return None
    assert process.stdin is not None and process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    try:
        requests = (
            {"id": 1, "method": "initialize", "params": {
                "clientInfo": {"name": "fairy-security-advisory", "version": "0.1.2"},
                "capabilities": {"experimentalApi": True},
            }},
            {"id": 2, "method": "account/rateLimits/read", "params": {
                "skipResetCreditsDetail": True,
                "supportsLunaReserveFallback": False,
            }},
        )
        process.stdin.write(json.dumps(requests[0]) + "\n")
        process.stdin.flush()
        sent_usage_request = False
        while time.monotonic() < deadline:
            ready = selector.select(max(0.0, deadline - time.monotonic()))
            if not ready:
                break
            line = process.stdout.readline()
            if not line:
                break
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("id") == 1 and not sent_usage_request:
                process.stdin.write(json.dumps(requests[1]) + "\n")
                process.stdin.flush()
                sent_usage_request = True
            elif message.get("id") == 2 and isinstance(message.get("result"), dict):
                return message["result"]
        return None
    except (OSError, BrokenPipeError, subprocess.SubprocessError):
        return None
    finally:
        selector.close()
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
        process.stdin.close()
        process.stdout.close()
