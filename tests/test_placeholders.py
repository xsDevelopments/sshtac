import shlex
import shutil
import subprocess
import unittest

from sshtac.placeholders import PlaceholderError, names, substitute

NASTY = ["simple", "has space", "it's", 'dq"x', "$(id)", "`id`", "a!b", "back\\slash",
         "semi;colon", "*glob?", "~tilde", "$HOME", "x' ; rm -rf / ; echo '", "--flag"]


class TestNames(unittest.TestCase):
    def test_order_and_dedupe(self):
        self.assertEqual(names("a {{B}} {{C}} {{B}} {{lower}}"), ["B", "C"])


class TestSubstitute(unittest.TestCase):
    def test_contexts(self):
        self.assertEqual(substitute("mysql -p{{PW}}", {"PW": "a b"}), "mysql -p'a b'")
        # inside '...': close the quote, insert shlex.quote(value), reopen
        self.assertEqual(substitute("echo '{{PW}}'", {"PW": "it's"}), "echo ''" + shlex.quote("it's") + "''")
        self.assertEqual(substitute('echo "x{{PW}}y"', {"PW": "q"}), 'echo "x"q"y"')

    def test_missing_and_bad_values(self):
        with self.assertRaises(PlaceholderError):
            substitute("echo {{A}}", {})
        with self.assertRaises(PlaceholderError):
            substitute("echo {{A}}", {"A": ""})
        for bad in ("a\nb", "a\x1bb", "a\rb", "a‮b", "a\tb"):
            with self.assertRaises(PlaceholderError, msg=repr(bad)):
                substitute("echo {{A}}", {"A": bad})
        with self.assertRaises(PlaceholderError):
            substitute("echo $'{{A}}'", {"A": "x"})
        with self.assertRaises(PlaceholderError):
            substitute("echo '{{A}}", {"A": "x"})

    def test_shell_sees_exact_value(self):
        """Run the substituted command in a real shell and compare."""
        sh = shutil.which("bash") or shutil.which("sh")
        if not sh:
            self.skipTest("no shell")
        templates = [
            "printf '%s' {{V}}",
            "printf '%s' '{{V}}'",
            'printf \'%s\' "{{V}}"',
            "printf '%s' pre{{V}}post",
            "printf '%s' 'pre{{V}}post'",
            'printf \'%s\' "pre{{V}}post"',
        ]
        for tpl in templates:
            for val in NASTY:
                cmd = substitute(tpl, {"V": val})
                out = subprocess.run([sh, "-c", cmd], capture_output=True, text=True, timeout=5).stdout
                want = val
                if "pre" in tpl:
                    want = "pre" + val + "post"
                with self.subTest(tpl=tpl, val=val):
                    self.assertEqual(out, want, cmd)

    def test_interactive_bash_history_expansion(self):
        """! must not trigger history expansion in an interactive shell."""
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("no bash")
        cmd = substitute('printf "%s" "{{V}}"', {"V": "a!!b"})
        out = subprocess.run([bash, "--norc", "-i", "-c", cmd], capture_output=True, text=True, timeout=5).stdout
        self.assertEqual(out, "a!!b")

    def test_policy_sees_quoted_value(self):
        from sshtac.policy import Risk, classify

        cmd = substitute("echo {{V}}", {"V": "x; rm -rf /"})
        self.assertEqual(shlex.split(cmd), ["echo", "x; rm -rf /"])
        self.assertEqual(classify(cmd).risk, Risk.READ_ONLY)


if __name__ == "__main__":
    unittest.main()
