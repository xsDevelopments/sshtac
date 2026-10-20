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



class TestCredentials(unittest.TestCase):
    """Key lookup order and the key file. TAC_CONFIG points at a temp dir, so
    the real ~/.config/tac is never touched."""

    def setUp(self):
        import os
        import tempfile
        from pathlib import Path

        self._env = dict(os.environ)
        for v in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE", "TAC_TEST_FAKE_MODEL"):
            os.environ.pop(v, None)
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["TAC_CONFIG"] = str(Path(self.tmp.name) / "tac" / "config.toml")

    def tearDown(self):
        import os

        os.environ.clear()
        os.environ.update(self._env)
        self.tmp.cleanup()

    def run_ask(self, typed="", save="n", ant_profile=False):
        import os
        from unittest import mock

        from tac import launcher

        prompts = []

        def fake_getpass(prompt):
            prompts.append(prompt)
            return typed

        def fake_input(prompt):
            prompts.append(prompt)
            return save

        with mock.patch("sys.stdin.isatty", return_value=True), \
                mock.patch.object(launcher, "has_credentials", return_value=ant_profile), \
                mock.patch("sys.stderr"):
            launcher.ask_for_key(fake_getpass, fake_input)
        return prompts, os.environ.get("ANTHROPIC_API_KEY")

    def test_prompt_key_goes_to_environment(self):
        prompts, key = self.run_ask("  sk-ant-test-123  \n")
        self.assertIn("hidden", prompts[0])
        self.assertEqual(key, "sk-ant-test-123")

    def test_prompt_offers_to_save_and_saves_privately(self):
        import os

        from tac import apikey

        self.run_ask("sk-ant-saved", save="y")
        p = apikey.path()
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
        self.assertEqual(apikey.read(), "sk-ant-saved")

    def test_declining_save_writes_nothing(self):
        from tac import apikey

        self.run_ask("sk-ant-x", save="")
        self.assertFalse(apikey.path().exists())

    def test_enter_skips(self):
        _, key = self.run_ask("")
        self.assertIsNone(key)

    def test_key_file_used_without_prompting(self):
        from tac import apikey

        apikey.write("sk-ant-from-file")
        prompts, key = self.run_ask("should-not-be-asked")
        self.assertEqual(prompts, [])
        self.assertEqual(key, "sk-ant-from-file")

    def test_key_file_beats_ant_profile_and_env_beats_key_file(self):
        import os

        from tac import apikey

        apikey.write("sk-ant-from-file")
        _, key = self.run_ask(ant_profile=True)
        self.assertEqual(key, "sk-ant-from-file")
        os.environ["ANTHROPIC_API_KEY"] = "sk-ant-from-env"
        _, key = self.run_ask()
        self.assertEqual(key, "sk-ant-from-env")

    def test_readable_key_file_refused(self):
        import os

        from tac import apikey

        p = apikey.write("sk-ant-x")
        os.chmod(p, 0o644)
        with self.assertRaises(apikey.KeyFileError) as e:
            apikey.read()
        self.assertIn("chmod 600", str(e.exception))
        prompts, key = self.run_ask("")  # falls back to the prompt
        self.assertTrue(prompts)
        self.assertIsNone(key)

    def test_key_file_formats(self):
        import os

        from tac import apikey

        p = apikey.path()
        p.parent.mkdir(parents=True, exist_ok=True)
        for content in ("sk-ant-a\n", "# my key\n\nsk-ant-a\n", 'ANTHROPIC_API_KEY="sk-ant-a"\n'):
            p.write_text(content)
            os.chmod(p, 0o600)
            self.assertEqual(apikey.read(), "sk-ant-a", content)
        p.write_text("\n# nothing\n")
        self.assertIsNone(apikey.read())

    def test_config_command_shows_status_never_the_key(self):
        import io
        from contextlib import redirect_stdout
        from unittest import mock

        from tac import apikey
        from tac.cli import main

        with mock.patch("getpass.getpass", return_value="sk-ant-secret-value"), redirect_stdout(io.StringIO()):
            self.assertEqual(main(["config", "--set-key"]), 0)
        self.assertEqual(apikey.read(), "sk-ant-secret-value")
        out = io.StringIO()
        with redirect_stdout(out):
            main(["config"])
        self.assertIn("API key: ", out.getvalue())
        self.assertIn("owner-only", out.getvalue())
        self.assertNotIn("sk-ant-secret-value", out.getvalue())
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["config", "--remove-key"]), 0)
        self.assertFalse(apikey.path().exists())

    def test_has_env_credentials(self):
        from tac.launcher import has_credentials, has_env_credentials

        self.assertTrue(has_env_credentials({"ANTHROPIC_API_KEY": "x"}))
        self.assertTrue(has_credentials({"ANTHROPIC_PROFILE": "work"}))
        self.assertFalse(has_env_credentials({}))


class TestConfigFile(unittest.TestCase):
    def test_example_matches_defaults_exactly(self):
        import tomllib

        with config.EXAMPLE.open("rb") as f:
            example = tomllib.load(f)
        self.assertEqual(example, config.DEFAULTS)

    def test_load_reports_source(self):
        import os
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "config.toml"
            self.assertIsNone(config.load(p).source)
            p.write_text('[keys]\napprove = "M-a"\n')
            cfg = config.load(p)
            self.assertEqual(cfg.source, str(p))
            self.assertEqual(cfg.keys["approve"], "M-a")

    def test_key_names(self):
        import copy

        for good in ("F7", "F12", "S-F7", "M-F7", "C-a", "M-a", "C-M-x", "M-Up"):
            data = copy.deepcopy(config.DEFAULTS)
            data["keys"]["approve"] = good
            config.from_dict(data)
        for bad in ("y", "a", "Enter", "Space", "F25", "C-", "F7; kill-server", ""):
            data = copy.deepcopy(config.DEFAULTS)
            data["keys"]["approve"] = bad
            with self.assertRaises(config.ConfigError, msg=bad):
                config.from_dict(data)

    def test_duplicate_keys_rejected(self):
        import copy

        data = copy.deepcopy(config.DEFAULTS)
        data["keys"]["approve"] = data["keys"]["reject"]
        with self.assertRaises(config.ConfigError):
            config.from_dict(data)

    def test_config_command(self):
        import io
        import os
        import tempfile
        from contextlib import redirect_stdout, redirect_stderr
        from pathlib import Path
        from unittest import mock

        from tac.cli import main

        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "tac" / "config.toml"
            with mock.patch.dict(os.environ, {"TAC_CONFIG": str(p)}):
                out = io.StringIO()
                with redirect_stdout(out):
                    self.assertEqual(main(["config", "--init"]), 0)
                self.assertEqual(p.read_text(), config.EXAMPLE.read_text())
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(main(["config", "--init"]), 1)  # never overwrites
                out = io.StringIO()
                with redirect_stdout(out):
                    self.assertEqual(main(["config"]), 0)
                self.assertIn("config OK", out.getvalue())
                p.write_text('[keys]\napprove = "y"\n')
                err = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(err):
                    self.assertEqual(main(["config"]), 1)
                self.assertIn("keys.approve", err.getvalue())


if __name__ == "__main__":
    unittest.main()
