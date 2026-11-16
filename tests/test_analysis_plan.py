# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import unittest

from scripts.analysis_plan import build_analysis_plan, plan_summary, required_providers


class AnalysisPlanTest(unittest.TestCase):
    def test_projects_are_excluded_or_routed_to_explicit_and_default_providers(self) -> None:
        plan = build_analysis_plan({"inventory": {"projects": [
            {"id": "default", "path": "/projects/default", "advisory_checks": {
                "enabled": True, "preferred_ai": None,
            }},
            {"id": "claude", "path": "/projects/claude", "advisory_checks": {
                "enabled": True, "preferred_ai": "claude",
            }},
            {"id": "off", "path": "/projects/off", "advisory_checks": {
                "enabled": False, "preferred_ai": "codex",
            }},
        ]}}, "codex")

        self.assertEqual([item["id"] for item in plan["groups"]["codex"]], ["default"])
        self.assertEqual([item["id"] for item in plan["groups"]["claude"]], ["claude"])
        self.assertEqual([item["id"] for item in plan["excluded"]], ["off"])
        self.assertEqual(required_providers(plan), ["codex", "claude"])
        self.assertEqual(plan_summary(plan), "Codex: 1 project(s); Claude: 1 project(s); excluded: 1")

    def test_only_coordinator_is_required_when_other_group_is_empty(self) -> None:
        plan = build_analysis_plan({"inventory": {"projects": [{
            "id": "api", "path": "/projects/api",
        }]}}, "claude")
        self.assertEqual(required_providers(plan), ["claude"])
        self.assertEqual(plan["groups"]["claude"][0]["id"], "api")


if __name__ == "__main__":
    unittest.main()
