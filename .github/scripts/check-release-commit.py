#!/usr/bin/env python3
"""Reject release-plz checkouts away from the commit validated by CI."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib


def run(*command: str) -> str:
    return subprocess.run(
        command, check=True, capture_output=True, text=True, encoding="utf-8", timeout=60
    ).stdout.strip()


def github_items(endpoint: str) -> list[dict]:
    pages = json.loads(run("gh", "api", "--paginate", "--slurp", endpoint))
    if not isinstance(pages, list) or not pages:
        raise ValueError("GitHub returned no response pages")
    items = []
    for page in pages:
        if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
            raise ValueError("GitHub returned an invalid response page")
        items.extend(page)
    return items


def check_release_commit(repository: str, sha: str, config_path: Path) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("GITHUB_REPOSITORY must be an owner/repository name")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("GITHUB_SHA must be a full commit SHA")
    if run("git", "rev-parse", "--verify", "HEAD") != sha:
        raise ValueError("HEAD differs from the commit validated by CI")

    with config_path.open("rb") as config_file:
        config = tomllib.load(config_file)
    prefix = config.get("workspace", {}).get("pr_branch_prefix", "release-plz-")
    if not isinstance(prefix, str):
        raise ValueError("pr_branch_prefix must be a string")

    ancestors = set(run("git", "rev-list", sha).splitlines())
    if sha not in ancestors:
        raise ValueError("Git did not return the verified commit's history")
    prs = github_items(f"repos/{repository}/commits/{sha}/pulls?per_page=100")
    for pr in prs:
        head = pr.get("head")
        if not isinstance(head, dict) or not isinstance(head.get("ref"), str):
            raise ValueError("GitHub returned a pull request without a head branch")
        if not head["ref"].startswith(prefix):
            continue
        number = pr.get("number")
        if type(number) is not int or number <= 0:
            raise ValueError("GitHub returned an invalid pull request number")
        commits = github_items(f"repos/{repository}/pulls/{number}/commits?per_page=100")
        if not commits:
            raise ValueError(f"GitHub returned no commits for release PR #{number}")
        # release-plz 0.3.171 selects the last commit on its first API page.
        # Check every page so both that commit and a paginated last commit are safe.
        # https://github.com/release-plz/release-plz/blob/release-plz-v0.3.171/crates/release_plz_core/src/command/release.rs
        for commit in commits:
            candidate = commit.get("sha")
            if not isinstance(candidate, str) or not re.fullmatch(r"[0-9a-f]{40}", candidate):
                raise ValueError(f"GitHub returned an invalid commit for PR #{number}")
            if candidate != sha and candidate in ancestors:
                raise ValueError(
                    f"Release PR #{number} includes ancestor {candidate}; release-plz "
                    "could publish an unverified commit. Squash-merge the release PR "
                    "or validate its exact release commit before publishing."
                )


def main() -> int:
    try:
        check_release_commit(
            os.environ.get("GITHUB_REPOSITORY", ""),
            os.environ.get("GITHUB_SHA", ""),
            Path(".release-plz.toml"),
        )
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Release commit check failed: {error}", file=sys.stderr)
        return 1
    print("Release commit check passed: release-plz cannot select an older commit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
