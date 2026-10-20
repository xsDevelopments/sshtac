import unittest

from tac import config
from tac.launcher import _shell_cmd, session_name, ssh_destination
from tac.tmuxctl import parse_version


class TestSshParsing(unittest.TestCase):
    def test_destination(self):
        cases = {
            ("host",): "host",
            ("user@host",): "user@host",
            ("-p", "2222", "host"): "host",
            ("-p2222", "host"): "host",
            ("-vvA", "host", "uptime"): "host",
            ("-o", "BatchMode=yes", "-i", "~/.ssh/k", "u@h"): "u@h",
            ("-J", "bastion", "inner"): "inner",
            ("--", "host"): "host",
            ("-v",): None,
            (): None,
        }
        for args, want in cases.items():
            self.assertEqual(ssh_destination(list(args)), want, args)

    def test_session_name(self):
        self.assertEqual(session_name([]), "tac-local")
        self.assertEqual(session_name(["admin@web-01.example.com"]), "tac-web-01-example-com")
        self.assertEqual(session_name(["ssh://u@h.x:22"]), "tac-h-x-22")
        self.assertEqual(session_name(["-p", "22", "a;b$(c)"]), "tac-a-b-c")
        self.assertRegex(session_name(["x" * 200]), r"^tac-x{40}$")


class TestShellCmd(unittest.TestCase):
    def test_quoting_and_hash_escape(self):
        cmd = _shell_cmd(["/opt/py #3/python", "-m", "tac"], {"PYTHONPATH": "/a b"})
        self.assertEqual(cmd, "env PYTHONPATH='/a b' '/opt/py ##3/python' -m tac")


class TestTmuxVersion(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_version("tmux 3.4\n"), (3, 4))
        self.assertEqual(parse_version("tmux 3.3a"), (3, 3))
        self.assertEqual(parse_version("tmux next-3.5"), (3, 5))


class TestConfig(unittest.TestCase):
    def test_defaults_valid(self):
        cfg = config.from_dict(config.DEFAULTS)
        self.assertEqual(cfg.keys["send_results"], "F6")
        self.assertEqual(cfg.model, "claude-sonnet-5-5")

    def test_unknown_key_rejected(self):
        import copy

        data = copy.deepcopy(config.DEFAULTS)
        with self.assertRaises(config.ConfigError):
            config._merge(data, {"keys": {"approvee": "F7"}})

    def test_type_checked(self):
        import copy

        data = copy.deepcopy(config.DEFAULTS)
        with self.assertRaises(config.ConfigError):
            config._merge(data, {"capture": {"max_chars": "lots"}})

    def test_bad_key_name(self):
        import copy

        data = copy.deepcopy(config.DEFAULTS)
        data["keys"]["approve"] = "F7; kill-server"
        with self.assertRaises(config.ConfigError):
            config.from_dict(data)

    def test_bad_regex(self):
        import copy

        data = copy.deepcopy(config.DEFAULTS)
        data["redaction"]["patterns"] = [{"name": "x", "regex": "("}]
        with self.assertRaises(config.ConfigError):
            config.from_dict(data)



class TestCredentialsPrompt(unittest.TestCase):
    def setUp(self):
        import os

        self._env = dict(os.environ)
        for v in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE", "TAC_TEST_FAKE_MODEL"):
            os.environ.pop(v, None)

    def tearDown(self):
        import os

        os.environ.clear()
        os.environ.update(self._env)

    def _ask(self, answer):
        import os
        from unittest import mock

        from tac import launcher

        prompts = []

        def fake_getpass(prompt):
            prompts.append(prompt)
            return answer

        with mock.patch("sys.stdin.isatty", return_value=True), \
                mock.patch.object(launcher, "has_credentials", return_value=False), \
                mock.patch("sys.stderr"):
            launcher.ask_for_key(fake_getpass)
        return prompts, os.environ.get("ANTHROPIC_API_KEY")

    def test_key_goes_to_environment_only(self):
        prompts, key = self._ask("  sk-ant-test-123  \n")
        self.assertEqual(len(prompts), 1)
        self.assertIn("hidden", prompts[0])
        self.assertEqual(key, "sk-ant-test-123")

    def test_enter_skips(self):
        _, key = self._ask("")
        self.assertIsNone(key)

    def test_not_asked_when_credentials_exist(self):
        from tac.launcher import has_credentials

        self.assertTrue(has_credentials({"ANTHROPIC_API_KEY": "x"}))
        self.assertTrue(has_credentials({"ANTHROPIC_PROFILE": "work"}))


if __name__ == "__main__":
    unittest.main()
