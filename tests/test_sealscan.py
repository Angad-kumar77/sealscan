import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from sealscan.cli import main
from sealscan.ignore import IgnoreRules
from sealscan.rules import classify_spdx, classify_text
from sealscan.scanner import ScanOptions, scan

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel, content):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def run_scan(self, **kw):
        return scan(str(self.root), ScanOptions(**kw))

    def ids(self, result):
        return {f.rule_id for f in result.findings}

    def cli(self, *args):
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            code = main([str(a) for a in args])
        return code, buf.getvalue(), err.getvalue()


class SecretTests(Base):
    def test_aws_key(self):
        self.write("app.py", 'k = "%s"\n' % AWS_KEY)
        self.assertIn("SECRET-AWS-ACCESS-KEY", self.ids(self.run_scan()))

    def test_github_token_wins_over_generic(self):
        self.write("a.py", 'token = "%s"\n' % GH_TOKEN)
        ids = self.ids(self.run_scan())
        self.assertIn("SECRET-GITHUB-TOKEN", ids)
        self.assertNotIn("SECRET-GENERIC-CREDENTIAL", ids)

    def test_generic_credential(self):
        self.write("a.py", 'api_key = "f8Kd92JsLq03Xz7Vb1"\n')
        self.assertIn("SECRET-GENERIC-CREDENTIAL", self.ids(self.run_scan()))

    def test_placeholders_ignored(self):
        self.write("a.py", 'password = "your_password_here"\n'
                           'api_key = os.environ["API_KEY"]\n'
                           'token = "${TOKEN_VALUE}"\n')
        self.assertEqual(self.run_scan().findings, [])

    def test_private_key_block(self):
        self.write("k.txt", "-----BEGIN RSA PRIVATE KEY-----\n")
        self.assertIn("SECRET-PRIVATE-KEY", self.ids(self.run_scan()))

    def test_url_credentials(self):
        self.write("a.py", 'DB = "postgres://admin:Xk29fj3Lqp@db.internal/app"\n')
        self.assertIn("SECRET-URL-CREDENTIALS", self.ids(self.run_scan()))

    def test_secret_is_redacted(self):
        self.write("a.py", 'k = "%s"\n' % AWS_KEY)
        f = self.run_scan().findings[0]
        self.assertNotIn(AWS_KEY, f.snippet)

    def test_env_file_flagged_unless_ignored(self):
        self.write(".env", "A=1\n")
        self.write(".env.example", "A=\n")
        res = self.run_scan()
        self.assertEqual([f.path for f in res.findings if f.rule_id == "SECRET-ENV-FILE"], [".env"])
        self.write(".gitignore", ".env\n")
        self.assertNotIn("SECRET-ENV-FILE", self.ids(self.run_scan()))

    def test_inline_ignore(self):
        self.write("a.py", 'k = "%s"  # sealscan:ignore\n' % AWS_KEY)
        self.assertEqual(self.run_scan().findings, [])


class VulnTests(Base):
    def test_python_rules(self):
        self.write("a.py", "x = eval(data)\nsubprocess.run(cmd, shell=True)\n"
                           "requests.get(u, verify=False)\n")
        ids = self.ids(self.run_scan())
        self.assertTrue({"VULN-PY-EVAL", "VULN-PY-SHELL-TRUE", "VULN-PY-TLS-VERIFY-OFF"} <= ids)

    def test_no_false_positive_eval_variants(self):
        self.write("a.py", "model.eval()\nast.literal_eval(x)\n# eval(x)\n")
        self.assertEqual(self.run_scan().findings, [])

    def test_yaml_safe_loader_ok(self):
        self.write("a.py", "yaml.load(f, Loader=yaml.SafeLoader)\nyaml.safe_load(f)\n")
        self.assertEqual(self.run_scan().findings, [])
        self.write("b.py", "yaml.load(f)\n")
        self.assertIn("VULN-PY-YAML-LOAD", self.ids(self.run_scan()))

    def test_rules_respect_file_type(self):
        self.write("a.js", "el.innerHTML = x;\n")
        self.assertIn("VULN-JS-INNERHTML", self.ids(self.run_scan()))
        (self.root / "a.js").unlink()
        self.write("a.py", "el.innerHTML = x\n")
        self.assertEqual(self.run_scan().findings, [])


class LicenseTests(Base):
    def test_agpl_license_file(self):
        self.write("LICENSE", "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3\n")
        self.assertIn("LICENSE-AGPL", self.ids(self.run_scan()))

    def test_lgpl_not_reported_as_gpl(self):
        self.write("LICENSE", "GNU LESSER GENERAL PUBLIC LICENSE\nsee the GNU General Public License\n")
        ids = self.ids(self.run_scan())
        self.assertEqual(ids, {"LICENSE-LGPL"})

    def test_mit_is_clean(self):
        self.write("LICENSE", "MIT License\n\nPermission is hereby granted, free of charge\n")
        self.assertEqual(self.run_scan().findings, [])

    def test_package_json(self):
        self.write("package.json", '{"name": "x", "license": "GPL-3.0"}')
        self.assertIn("LICENSE-GPL", self.ids(self.run_scan()))
        self.write("package.json", '{"name": "x", "license": "MIT"}')
        self.assertEqual(self.run_scan().findings, [])

    def test_pyproject_classifier(self):
        self.write("pyproject.toml",
                   'classifiers = ["License :: OSI Approved :: GNU General Public License v3 (GPLv3)"]\n')
        self.assertIn("LICENSE-GPL", self.ids(self.run_scan()))

    def test_spdx_header(self):
        self.write("a.py", "# SPDX-License-Identifier: AGPL-3.0-or-later\n")
        self.assertIn("LICENSE-AGPL", self.ids(self.run_scan()))

    def test_classifiers(self):
        self.assertEqual(classify_text("GNU GENERAL PUBLIC LICENSE v3").id, "LICENSE-GPL")
        self.assertEqual([r.id for r in classify_spdx("(MIT OR GPL-2.0+)")], ["LICENSE-GPL"])
        self.assertEqual(classify_spdx("Apache-2.0"), [])


class IgnoreTests(Base):
    def test_gitignore_rules(self):
        self.write(".gitignore", "build/\n*.log\n!keep.log\n/only_root.py\n")
        bad = 'k = "%s"\n' % AWS_KEY
        self.write("build/x.py", bad)
        self.write("a.log", bad)
        self.write("keep.log", bad)
        self.write("only_root.py", bad)
        self.write("sub/only_root.py", bad)
        paths = {f.path for f in self.run_scan().findings}
        self.assertEqual(paths, {"keep.log", "sub/only_root.py"})

    def test_no_gitignore_option(self):
        self.write(".gitignore", "a.py\n")
        self.write("a.py", 'k = "%s"\n' % AWS_KEY)
        self.assertEqual(self.run_scan().findings, [])
        self.assertTrue(self.run_scan(use_gitignore=False).findings)

    def test_nested_gitignore(self):
        self.write("sub/.gitignore", "secret.py\n")
        self.write("sub/secret.py", 'k = "%s"\n' % AWS_KEY)
        self.write("secret.py", 'k = "%s"\n' % AWS_KEY)
        self.assertEqual({f.path for f in self.run_scan().findings}, {"secret.py"})

    def test_sealscanignore_and_extra_ignores(self):
        self.write(".sealscanignore", "vendor/\n")
        self.write("vendor/a.py", 'k = "%s"\n' % AWS_KEY)
        self.write("skip_me/a.py", 'k = "%s"\n' % AWS_KEY)
        self.write("keep/a.py", 'k = "%s"\n' % AWS_KEY)
        res = self.run_scan(extra_ignores=["skip_me/"])
        self.assertEqual({f.path for f in res.findings}, {"keep/a.py"})

    def test_glob_patterns(self):
        rules = IgnoreRules(str(self.root), ["docs/**/*.md", "*.tmp"])
        self.assertTrue(rules.match(str(self.root / "docs/a/b/x.md"), False))
        self.assertTrue(rules.match(str(self.root / "deep/er/y.tmp"), False))
        self.assertIsNone(rules.match(str(self.root / "other/x.md"), False))

    def test_default_skip_dirs(self):
        self.write("node_modules/pkg/a.js", 'var k = "%s";\n' % AWS_KEY)
        self.assertEqual(self.run_scan().findings, [])


class OptionTests(Base):
    def setUp(self):
        super().setUp()
        self.write("a.py", 'k = "%s"\nx = eval(y)\nh = hashlib.md5(z)\n' % AWS_KEY)

    def test_min_severity(self):
        self.assertEqual({f.severity for f in self.run_scan(min_severity="critical").findings}, {"critical"})

    def test_disabled_rules(self):
        self.assertNotIn("VULN-PY-EVAL", self.ids(self.run_scan(disabled_rules={"VULN-PY-EVAL"})))

    def test_categories(self):
        self.assertEqual({f.category for f in self.run_scan(categories={"secret"}).findings}, {"secret"})

    def test_single_file_target(self):
        res = scan(str(self.root / "a.py"))
        self.assertTrue(res.findings)
        self.assertEqual(res.findings[0].path, "a.py")


class CliTests(Base):
    def test_exit_codes(self):
        self.write("a.py", "x = eval(y)\n")
        self.assertEqual(self.cli(self.root)[0], 1)
        self.assertEqual(self.cli(self.root, "--fail-on", "critical")[0], 0)
        self.assertEqual(self.cli(self.root / "missing")[0], 2)

    def test_clean_project(self):
        self.write("a.py", "print('hi')\n")
        code, out, _ = self.cli(self.root)
        self.assertEqual(code, 0)
        self.assertIn("no issues found", out)

    def test_json_output(self):
        self.write("a.py", 'k = "%s"\n' % AWS_KEY)
        code, out, _ = self.cli(self.root, "--format", "json")
        data = json.loads(out)
        self.assertEqual(data["findings"][0]["rule_id"], "SECRET-AWS-ACCESS-KEY")
        self.assertNotIn(AWS_KEY, out)

    def test_sarif_output(self):
        self.write("a.py", "x = eval(y)\n")
        code, out, _ = self.cli(self.root, "--format", "sarif")
        doc = json.loads(out)
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["results"][0]["ruleId"], "VULN-PY-EVAL")
        self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"], 1)
        self.assertTrue(run["tool"]["driver"]["rules"])

    def test_output_file(self):
        self.write("a.py", "x = eval(y)\n")
        out_file = self.root.parent / (self.root.name + "_report.json")
        try:
            self.cli(self.root, "--format", "json", "-o", out_file)
            self.assertIn("findings", json.loads(out_file.read_text(encoding="utf-8")))
        finally:
            out_file.unlink()

    def test_config_file(self):
        self.write("a.py", "x = eval(y)\n")
        self.write("skipme/b.py", "x = eval(y)\n")
        self.write(".sealscan.json", json.dumps({"ignore": ["skipme/"], "disable_rules": ["VULN-PY-EVAL"]}))
        code, out, _ = self.cli(self.root)
        self.assertEqual(code, 0)
        self.assertIn("no issues found", out)

    def test_bad_config(self):
        self.write(".sealscan.json", '{"nope": 1}')
        self.assertEqual(self.cli(self.root)[0], 2)

    def test_unknown_rule_and_category(self):
        self.assertEqual(self.cli(self.root, "--disable", "NOT-A-RULE")[0], 2)
        self.assertEqual(self.cli(self.root, "--only", "bogus")[0], 2)

    def test_list_rules(self):
        code, out, _ = self.cli("--list-rules")
        self.assertEqual(code, 0)
        self.assertIn("SECRET-AWS-ACCESS-KEY", out)


if __name__ == "__main__":
    unittest.main()
