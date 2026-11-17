# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import datetime as dt
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts.release_cache import (
    export_shared_candidates, LOCAL_CACHE, ReleaseCacheError, resolve_release_metadata,
    SHARED_CANDIDATES,
)


class _Response:
    def __init__(self, payload: dict) -> None:
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit: int = -1) -> bytes:
        return self.payload


class ReleaseCacheTest(unittest.TestCase):
    def test_future_negative_cache_entry_does_not_suppress_lookup(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            shared = root / "data/release-cache/entries.json"
            shared.parent.mkdir(parents=True)
            shared.write_text(json.dumps({"schema_version": 1, "entries": {
                "npm|demo|1.0.0": {"status": "not-found", "ecosystem": "npm",
                    "name": "demo", "version": "1.0.0", "checked_at": "2099-01-01T00:00:00Z"},
            }}), encoding="utf-8")
            technology = {"key": "demo-key", "ecosystem": "npm", "name": "demo",
                          "version": "1.0.0", "public_registry": True}
            with patch("scripts.release_cache.urllib.request.urlopen", side_effect=OSError) as fetch:
                resolve_release_metadata(root, [technology],
                    now=dt.datetime(2026, 11, 17, tzinfo=dt.timezone.utc))
            fetch.assert_called_once()

    def test_negative_cache_timestamp_requires_timezone(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            shared = root / "data/release-cache/entries.json"
            shared.parent.mkdir(parents=True)
            shared.write_text(json.dumps({"schema_version": 1, "entries": {
                "npm|express|4.17.1": {"status": "not-found", "ecosystem": "npm",
                    "name": "express", "version": "4.17.1", "checked_at": "2026-11-17"},
            }}), encoding="utf-8")
            with self.assertRaisesRegex(ReleaseCacheError, "invalid date"):
                resolve_release_metadata(root, [{"key": "express-key", "ecosystem": "npm",
                    "name": "express", "version": "4.17.1", "public_registry": True}],
                    online_enabled=False)

    def test_shared_platform_line_overrides_local_negative(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            shared = root / "data/release-cache/entries.json"
            shared.parent.mkdir(parents=True)
            shared.write_text(json.dumps({"schema_version": 1, "entries": {
                "platform|php|8.3": {"status": "verified", "ecosystem": "platform",
                    "name": "php", "version": "8.3", "baseline_version": "8.3.0",
                    "release_date": "2023-11-23", "source_url": "https://www.php.net/releases/8.3/en.php"},
            }}), encoding="utf-8")
            local = root / LOCAL_CACHE
            local.parent.mkdir(parents=True)
            local.write_text(json.dumps({"schema_version": 1, "entries": {
                "platform|php|8.3": {"status": "not-found", "ecosystem": "platform",
                    "name": "php", "version": "8.3", "checked_at": "2026-11-17T00:00:00Z"},
            }}), encoding="utf-8")
            result = resolve_release_metadata(root, [{"key": "php-key", "category": "runtimes",
                "name": "PHP", "version": "8.3.4"}], online_enabled=False)
            self.assertEqual(result["php-key"]["baseline_version"], "8.3.0")

    def test_private_or_unknown_registry_package_is_never_sent_online(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            shared = root / "data/release-cache/entries.json"
            shared.parent.mkdir(parents=True)
            shared.write_text('{"schema_version":1,"entries":{}}', encoding="utf-8")
            technology = {
                "key": "private-123", "ecosystem": "npm",
                "name": "@company/private", "version": "1.0.0",
            }
            with patch("scripts.release_cache.urllib.request.urlopen") as fetch:
                result = resolve_release_metadata(root, [technology], online_enabled=True)
            self.assertEqual(result, {})
            fetch.assert_not_called()

    def test_verified_local_entries_can_be_exported_for_human_review(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            local = root / LOCAL_CACHE
            local.parent.mkdir(parents=True)
            local.write_text(json.dumps({
                "schema_version": 1,
                "entries": {
                    "npm|demo|1.0.0": {"status": "verified", "ecosystem": "npm", "name": "demo", "version": "1.0.0", "release_date": "2024-01-01", "source_url": "https://api.deps.dev/demo"},
                    "npm|missing|1.0.0": {"status": "not-found", "ecosystem": "npm", "name": "missing", "version": "1.0.0"},
                },
            }), encoding="utf-8")
            path = export_shared_candidates(root)
            payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(path, root / SHARED_CANDIDATES)
        self.assertEqual(list(payload["entries"]), ["npm|demo|1.0.0"])

    def test_deps_dev_result_is_cached_and_reused_offline(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            shared = root / "data/release-cache/entries.json"
            shared.parent.mkdir(parents=True)
            shared.write_text('{"schema_version":1,"entries":{}}', encoding="utf-8")
            technology = {
                "key": "demo-123", "ecosystem": "npm", "name": "demo", "version": "1.2.3",
                "public_registry": True,
            }
            payload = {"responses": [{"request": {"versionKey": {
                "system": "NPM", "name": "demo", "version": "1.2.3",
            }}, "version": {"publishedAt": "2024-02-03T10:00:00Z"}}]}
            with patch("scripts.release_cache.urllib.request.urlopen", return_value=_Response(payload)) as fetch:
                first = resolve_release_metadata(
                    root, [technology], now=dt.datetime(2026, 11, 17, tzinfo=dt.timezone.utc),
                )
            self.assertEqual(first["demo-123"]["release_date"], "2024-02-03T10:00:00Z")
            self.assertTrue((root / LOCAL_CACHE).is_file())
            with patch("scripts.release_cache.urllib.request.urlopen") as second_fetch:
                second = resolve_release_metadata(root, [technology], online_enabled=False)
            self.assertEqual(second["demo-123"]["release_date"], "2024-02-03T10:00:00Z")
            fetch.assert_called_once()
            second_fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
