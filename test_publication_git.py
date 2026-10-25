import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / ".github/scripts/push-update.sh"
BASH = shutil.which("bash") or ("C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else None)


@unittest.skipUnless(BASH and shutil.which("git"), "Git and Bash required")
class PublicationGitTests(unittest.TestCase):
    def setUp(self):
        (ROOT / ".tmp").mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / ".tmp")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_TERMINAL_PROMPT": "0", "GIT_EDITOR": "true", "GIT_SEQUENCE_EDITOR": "true"}
        self.remote, self.runner, self.other = [self.root / n for n in ("remote.git", "runner", "other")]
        self.git(self.root, "init", "--bare", "--initial-branch=main", str(self.remote))
        self.git(self.root, "clone", str(self.remote), str(self.runner))
        self.configure(self.runner)
        self.commit_file(self.runner, "build.py", "original generator\n")
        self.commit_file(self.runner, "all.txt", "old subscription\n")
        self.git(self.runner, "push", "origin", "main")
        self.git(self.root, "clone", str(self.remote), str(self.other))
        self.configure(self.other)
        self.commit_file(self.runner, "all.txt", "validated subscription\n")

    def git(self, cwd, *args):
        result = subprocess.run(["git", *args], cwd=cwd, env=self.env, capture_output=True,
                                text=True, encoding="utf-8", errors="replace")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout.strip()

    def configure(self, repo):
        self.git(repo, "config", "user.name", "Publication Test")
        self.git(repo, "config", "user.email", "publication@example.invalid")

    def commit_file(self, repo, filename, text):
        (repo / filename).write_text(text, encoding="utf-8")
        self.git(repo, "add", filename)
        self.git(repo, "commit", "-m", "test " + filename)

    def publish(self):
        result = subprocess.run([BASH, str(SCRIPT)], cwd=self.runner, env=self.env,
                                capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def remote_file(self, filename):
        return self.git(self.root, "--git-dir", str(self.remote), "show", "main:" + filename)

    def test_rebases_and_publishes_without_losing_concurrent_commit(self):
        self.commit_file(self.other, "README.md", "concurrent documentation\n")
        self.git(self.other, "push", "origin", "main")
        self.publish()
        self.assertEqual(self.remote_file("all.txt"), "validated subscription")
        self.assertEqual(self.remote_file("README.md"), "concurrent documentation")

    def test_skips_stale_output_when_generator_changed(self):
        self.commit_file(self.other, "build.py", "new generator\n")
        self.git(self.other, "push", "origin", "main")
        message = self.publish()
        self.assertIn("generator changed", message)
        self.assertEqual(self.remote_file("build.py"), "new generator")
        self.assertEqual(self.remote_file("all.txt"), "old subscription")

    def test_keeps_remote_subscription_when_generated_files_conflict(self):
        self.commit_file(self.other, "all.txt", "newer subscription\n")
        self.git(self.other, "push", "origin", "main")
        message = self.publish()
        self.assertIn("conflict", message)
        self.assertEqual(self.remote_file("all.txt"), "newer subscription")
        self.assertFalse((self.runner / ".git/rebase-merge").exists())

    def test_push_rejection_stops_after_three_attempts_and_reports_failure(self):
        hook = self.remote / "hooks/pre-receive"
        hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        hook.chmod(0o755)
        result = subprocess.run([BASH, str(SCRIPT)], cwd=self.runner, env=self.env,
                                capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.count("Push attempt "), 3)
        self.assertEqual(self.remote_file("all.txt"), "old subscription")


if __name__ == "__main__":
    unittest.main()
