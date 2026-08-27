import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ContinuousMonitorTests(unittest.TestCase):
    def test_github_actions_has_read_only_permissions_and_no_secrets(self):
        workflow = (ROOT / ".github/workflows/flop-health-monitor.yml").read_text(encoding="utf-8")
        self.assertIn("contents: read", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertIn("--public --no-save", workflow)
        self.assertNotIn("git push", workflow)

    def test_twice_daily_jst_schedule(self):
        workflow = (ROOT / ".github/workflows/flop-health-monitor.yml").read_text(encoding="utf-8")
        self.assertIn('cron: "0 0,12 * * *"', workflow)
        self.assertIn("workflow_dispatch:", workflow)

    def test_no_room_probe_or_external_publish(self):
        workflow = (ROOT / ".github/workflows/flop-health-monitor.yml").read_text(encoding="utf-8")
        forbidden = ("post_signed", "create-room", "mailbox", "did note update", "x post")
        for marker in forbidden:
            self.assertNotIn(marker, workflow.lower())


if __name__ == "__main__":
    unittest.main()
