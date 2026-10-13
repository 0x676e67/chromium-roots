"""Tests for the release-plz publication boundary; no network or publishing."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import mock_open, patch


SPEC = importlib.util.spec_from_file_location(
    "check_release_commit", Path(__file__).with_name("check-release-commit.py")
)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)

SHA = "a" * 40
ANCESTOR = "b" * 40
SQUASHED = "c" * 40
REPOSITORY = "0x676e67/chromium-roots"
PR_ENDPOINT = f"repos/{REPOSITORY}/commits/{SHA}/pulls?per_page=100"
COMMITS_ENDPOINT = f"repos/{REPOSITORY}/pulls/7/commits?per_page=100"


class ReleaseCommitTests(unittest.TestCase):
    def setUp(self):
        self.config = Path(".release-plz.toml")
        self.config_data = b"[workspace]\nrelease_always = false\n"
        self.responses = {
            ("git", "rev-parse", "--verify", "HEAD"): SHA,
            ("git", "rev-list", SHA): f"{SHA}\n{ANCESTOR}",
            ("gh", "api", "--paginate", "--slurp", PR_ENDPOINT): json.dumps(
                [[{"number": 7, "head": {"ref": "release-plz-test"}}]]
            ),
        }

    def run_command(self, *command):
        response = self.responses[command]
        if isinstance(response, Exception):
            raise response
        return response

    def check(self, pages):
        self.responses[("gh", "api", "--paginate", "--slurp", COMMITS_ENDPOINT)] = json.dumps(pages)
        with (
            patch.object(guard, "run", side_effect=self.run_command),
            patch.object(guard.Path, "open", mock_open(read_data=self.config_data)),
        ):
            guard.check_release_commit(REPOSITORY, SHA, self.config)

    def test_same_commit_is_allowed(self):
        self.check([[{"sha": SHA}]])

    def test_squashed_commit_is_allowed(self):
        self.check([[{"sha": SQUASHED}]])

    def test_no_release_pr_is_allowed(self):
        self.responses[("gh", "api", "--paginate", "--slurp", PR_ENDPOINT)] = json.dumps(
            [[{"number": 7, "head": {"ref": "fix-workflows"}}]]
        )
        self.check([])

    def test_ancestor_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "could publish an unverified commit"):
            self.check([[{"sha": ANCESTOR}]])

    def test_intermediate_commit_is_rejected_across_pages(self):
        # The final commit alone is safe, but release-plz 0.3.171 can select
        # an earlier API page's last commit instead.
        with self.assertRaisesRegex(ValueError, "could publish an unverified commit"):
            self.check([[{"sha": ANCESTOR}], [{"sha": SQUASHED}]])

    def test_release_pr_on_later_page_is_checked(self):
        self.responses[("gh", "api", "--paginate", "--slurp", PR_ENDPOINT)] = json.dumps(
            [[], [{"number": 7, "head": {"ref": "release-plz-test"}}]]
        )
        with self.assertRaisesRegex(ValueError, "could publish an unverified commit"):
            self.check([[{"sha": ANCESTOR}]])

    def test_api_failure_exits_unsuccessfully(self):
        command = ("gh", "api", "--paginate", "--slurp", PR_ENDPOINT)
        self.responses[command] = subprocess.CalledProcessError(1, command)
        with (
            patch.object(guard, "run", side_effect=self.run_command),
            patch.object(guard.Path, "open", mock_open(read_data=b"[workspace]\n")),
            patch.dict(guard.os.environ, {"GITHUB_REPOSITORY": REPOSITORY, "GITHUB_SHA": SHA}),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(guard.main(), 1)

    def test_mismatched_checkout_is_rejected(self):
        self.responses[("git", "rev-parse", "--verify", "HEAD")] = ANCESTOR
        with self.assertRaisesRegex(ValueError, "HEAD differs"):
            self.check([[{"sha": SHA}]])

    def test_configured_branch_prefix_is_used(self):
        self.config_data = b'[workspace]\npr_branch_prefix = "custom-"\n'
        self.responses[("gh", "api", "--paginate", "--slurp", PR_ENDPOINT)] = json.dumps(
            [[{"number": 7, "head": {"ref": "custom-release"}}]]
        )
        with self.assertRaisesRegex(ValueError, "could publish an unverified commit"):
            self.check([[{"sha": ANCESTOR}]])

    def test_malformed_api_response_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid response page"):
            self.check([{"message": "API failure"}])


if __name__ == "__main__":
    unittest.main()
