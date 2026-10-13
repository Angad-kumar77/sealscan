"""Detection rules. Pure data plus tiny helpers, no I/O."""
import re
from typing import List

from sealscan.models import Rule

PY = frozenset({".py"})
JS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})
JAVA = frozenset({".java"})
GO = frozenset({".go"})

DOCKERFILE_NAMES = frozenset({"dockerfile"})
COMPOSE_NAMES = frozenset({
    "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
})
DEPENDENCY_MANIFESTS = frozenset({"requirements.txt", "package.json"})

# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------
SECRET_RULES = [
    Rule("SECRET-AWS-ACCESS-KEY", "AWS access key ID", "critical", "secret",
         "AWS access key ID found",
         re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Rule("SECRET-GITHUB-TOKEN", "GitHub token", "critical", "secret",
         "GitHub token found",
         re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    Rule("SECRET-GITLAB-TOKEN", "GitLab token", "critical", "secret",
         "GitLab personal access token found",
         re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b")),
    Rule("SECRET-SLACK-TOKEN", "Slack token", "high", "secret",
         "Slack token found",
         re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    Rule("SECRET-SLACK-WEBHOOK", "Slack webhook URL", "high", "secret",
         "Slack incoming webhook URL found",
         re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    Rule("SECRET-STRIPE-LIVE-KEY", "Stripe live key", "critical", "secret",
         "Stripe live secret key found",
         re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{24,}\b")),
    Rule("SECRET-GOOGLE-API-KEY", "Google API key", "high", "secret",
         "Google API key found",
         re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    Rule("SECRET-SENDGRID-KEY", "SendGrid API key", "high", "secret",
         "SendGrid API key found",
         re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    Rule("SECRET-NPM-TOKEN", "npm access token", "critical", "secret",
         "npm access token found",
         re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    Rule("SECRET-ANTHROPIC-KEY", "Anthropic API key", "critical", "secret",
         "Anthropic API key found",
         re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{40,}\b")),
    Rule("SECRET-OPENAI-KEY", "OpenAI API key", "critical", "secret",
         "OpenAI API key found",
         re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{40,}\b")),
    Rule("SECRET-PRIVATE-KEY", "Private key block", "critical", "secret",
         "Private key material found",
         re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    Rule("SECRET-JWT", "JSON Web Token", "medium", "secret",
         "JSON Web Token found",
         re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    Rule("SECRET-TWILIO-KEY", "Twilio API key", "critical", "secret",
         "Twilio API key found",
         re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    Rule("SECRET-MAILGUN-KEY", "Mailgun API key", "high", "secret",
         "Mailgun API key found",
         re.compile(r"\bkey-[0-9a-f]{32}\b")),
    Rule("SECRET-HEROKU-API-KEY", "Heroku API key", "high", "secret",
         "Heroku API key found",
         re.compile(r"(?i)heroku[_-]?api[_-]?key[\w.-]*['\"]?\s*[:=]\s*['\"]"
                    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]")),
    Rule("SECRET-AZURE-STORAGE-KEY", "Azure storage account key", "critical", "secret",
         "Azure storage account key found",
         re.compile(r"\bAccountKey=[A-Za-z0-9+/]{80,}={0,2}")),
    Rule("SECRET-PAYPAL-BRAINTREE-TOKEN", "PayPal/Braintree access token", "critical", "secret",
         "PayPal/Braintree access token found",
         re.compile(r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b")),
    Rule("SECRET-DISCORD-BOT-TOKEN", "Discord bot token", "critical", "secret",
         "Discord bot token found",
         re.compile(r"\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b")),
    Rule("SECRET-DISCORD-WEBHOOK", "Discord webhook URL", "high", "secret",
         "Discord webhook URL found",
         re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+")),
    Rule("SECRET-TELEGRAM-BOT-TOKEN", "Telegram bot token", "high", "secret",
         "Telegram bot token found",
         re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
    # Generic rules run last and are skipped when a specific rule already matched.
    Rule("SECRET-URL-CREDENTIALS", "Credentials in URL", "high", "secret",
         "Password embedded in a connection string or URL",
         re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@'\"]+:([^\s@'\"/]{3,})@[^\s'\"]+"),
         generic=True),
    Rule("SECRET-GENERIC-CREDENTIAL", "Hardcoded credential", "medium", "secret",
         "Value assigned to a secret-looking name",
         re.compile(r"(?i)(?:api[_-]?key|secret|token|passwd|password|auth[_-]?key|private[_-]?key)"
                    r"[\w.-]*['\"]?\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"),
         generic=True),
]

# Values that look like placeholders or references are ignored by generic rules.
PLACEHOLDER_HINTS = (
    "example", "changeme", "change_me", "your_", "your-", "yourkey", "xxxx",
    "dummy", "sample", "placeholder", "todo", "fake", "test", "redacted",
    "****", "os.environ", "getenv", "process.env",
)

# Files that should not normally be committed.
SENSITIVE_FILE_RULES = [
    Rule("SECRET-ENV-FILE", "Environment file", "high", "secret",
         "Environment file is not ignored and may contain secrets"),
    Rule("SECRET-KEY-FILE", "Key or credential file", "medium", "secret",
         "File type usually holds private keys or credentials"),
]
SENSITIVE_NAMES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".npmrc", ".pypirc", ".netrc", ".htpasswd", "credentials.json",
}
SENSITIVE_EXTS = {".pem", ".p12", ".pfx", ".jks", ".keystore", ".kdbx"}
ENV_EXAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist")

# --------------------------------------------------------------------------
# Insecure code patterns
# --------------------------------------------------------------------------
VULN_RULES = [
    Rule("VULN-PY-EVAL", "eval() call", "high", "vulnerability",
         "eval() can execute arbitrary code",
         re.compile(r"(?<![\w.])eval\s*\("), exts=PY),
    Rule("VULN-PY-EXEC", "exec() call", "high", "vulnerability",
         "exec() can execute arbitrary code",
         re.compile(r"(?<![\w.])exec\s*\("), exts=PY),
    Rule("VULN-PY-SHELL-TRUE", "subprocess with shell=True", "high", "vulnerability",
         "shell=True enables command injection; pass a list instead",
         re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True"), exts=PY),
    Rule("VULN-PY-OS-SYSTEM", "os.system() call", "medium", "vulnerability",
         "os.system() is injection-prone; prefer subprocess with a list",
         re.compile(r"\bos\.system\s*\("), exts=PY),
    Rule("VULN-PY-PICKLE", "pickle load", "high", "vulnerability",
         "Unpickling untrusted data can execute arbitrary code",
         re.compile(r"\b(?:pickle|cPickle)\.loads?\s*\("), exts=PY),
    Rule("VULN-PY-YAML-LOAD", "Unsafe yaml.load", "high", "vulnerability",
         "yaml.load without SafeLoader can execute arbitrary code",
         re.compile(r"\byaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?C?Safe)"), exts=PY),
    Rule("VULN-PY-WEAK-HASH", "Weak hash (MD5/SHA1)", "medium", "vulnerability",
         "MD5 and SHA1 are weak for security purposes",
         re.compile(r"\bhashlib\.(?:md5|sha1)\s*\("), exts=PY),
    Rule("VULN-PY-TLS-VERIFY-OFF", "TLS verification disabled", "high", "vulnerability",
         "Certificate verification is disabled",
         re.compile(r"verify\s*=\s*False|_create_unverified_context"), exts=PY),
    Rule("VULN-PY-DEBUG-MODE", "Debug mode enabled", "medium", "vulnerability",
         "Debug mode must not be enabled in production",
         re.compile(r"\.run\([^)]*debug\s*=\s*True"), exts=PY),
    Rule("VULN-PY-SQL-FORMAT", "SQL built with string formatting", "medium", "vulnerability",
         "Use parameterized queries instead of string formatting",
         re.compile(r"(?i)\.execute\s*\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*(?:%|\+|\.format\s*\())"),
         exts=PY),
    Rule("VULN-PY-MKTEMP", "tempfile.mktemp() call", "medium", "vulnerability",
         "mktemp() is racy; use mkstemp() or NamedTemporaryFile()",
         re.compile(r"\btempfile\.mktemp\s*\("), exts=PY),
    Rule("VULN-JS-EVAL", "eval() call", "high", "vulnerability",
         "eval() can execute arbitrary code",
         re.compile(r"(?<![\w.])eval\s*\("), exts=JS),
    Rule("VULN-JS-NEW-FUNCTION", "new Function()", "high", "vulnerability",
         "new Function() compiles strings into code",
         re.compile(r"\bnew\s+Function\s*\("), exts=JS),
    Rule("VULN-JS-INNERHTML", "innerHTML assignment", "medium", "vulnerability",
         "Unsanitized HTML can lead to XSS",
         re.compile(r"\.innerHTML\s*=(?!=)|dangerouslySetInnerHTML"), exts=JS),
    Rule("VULN-JS-DOCUMENT-WRITE", "document.write()", "medium", "vulnerability",
         "document.write() is an XSS sink",
         re.compile(r"\bdocument\.write(?:ln)?\s*\("), exts=JS),
    Rule("VULN-JS-CHILD-PROCESS-EXEC", "child_process.exec()", "high", "vulnerability",
         "exec() runs a shell command; prefer execFile()",
         re.compile(r"\bchild_process\.exec(?:Sync)?\s*\("), exts=JS),
    Rule("VULN-JS-TLS-VERIFY-OFF", "TLS verification disabled", "high", "vulnerability",
         "Certificate verification is disabled",
         re.compile(r"rejectUnauthorized\s*:\s*false"), exts=JS),
    Rule("VULN-JAVA-RUNTIME-EXEC", "Runtime.exec() call", "high", "vulnerability",
         "Runtime.exec() with untrusted input enables command injection",
         re.compile(r"\bRuntime\.getRuntime\(\)\.exec\s*\("), exts=JAVA),
    Rule("VULN-JAVA-OBJECT-DESERIALIZATION", "ObjectInputStream deserialization", "high", "vulnerability",
         "Deserializing untrusted data can execute arbitrary code",
         re.compile(r"\bnew\s+ObjectInputStream\s*\("), exts=JAVA),
    Rule("VULN-JAVA-WEAK-HASH", "Weak hash (MD5/SHA1)", "medium", "vulnerability",
         "MD5 and SHA1 are weak for security purposes",
         re.compile(r"MessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA1|SHA-1)[\"']"), exts=JAVA),
    Rule("VULN-JAVA-TRUST-ALL-CERTS", "TLS verification disabled", "high", "vulnerability",
         "A permissive TrustManager disables certificate verification",
         re.compile(r"\bX509TrustManager\b"), exts=JAVA),
    Rule("VULN-JAVA-SQL-CONCAT", "SQL built with string concatenation", "medium", "vulnerability",
         "Use PreparedStatement instead of concatenating SQL strings",
         re.compile(r"(?i)\.(?:execute|executeQuery|executeUpdate)\s*\(\s*\"[^\"]*\"\s*\+"), exts=JAVA),
    Rule("VULN-GO-EXEC-COMMAND", "exec.Command with shell", "high", "vulnerability",
         "Running a shell via exec.Command enables command injection",
         re.compile(r"exec\.Command\s*\(\s*\"(?:sh|bash|cmd|powershell)\""), exts=GO),
    Rule("VULN-GO-WEAK-HASH", "Weak hash (MD5/SHA1)", "medium", "vulnerability",
         "MD5 and SHA1 are weak for security purposes",
         re.compile(r"\b(?:md5|sha1)\.(?:New|Sum)\s*\("), exts=GO),
    Rule("VULN-GO-TLS-VERIFY-OFF", "TLS verification disabled", "high", "vulnerability",
         "Certificate verification is disabled",
         re.compile(r"InsecureSkipVerify\s*:\s*true"), exts=GO),
    Rule("VULN-GO-SQL-SPRINTF", "SQL built with fmt.Sprintf", "medium", "vulnerability",
         "Use parameterized queries instead of formatting SQL strings",
         re.compile(r"(?i)(?:db|tx)\.(?:Query|Exec)(?:Context)?\s*\(\s*(?:ctx,\s*)?fmt\.Sprintf"), exts=GO),
]

# --------------------------------------------------------------------------
# Config / infra security (Dockerfiles, docker-compose, generic headers)
# --------------------------------------------------------------------------
CONFIG_RULES = [
    Rule("CONFIG-DOCKER-LATEST-TAG", "Dockerfile base image pinned to :latest", "medium", "config",
         "Pin a specific image tag/digest instead of :latest for reproducible builds",
         re.compile(r"(?im)^\s*FROM\s+\S+:latest\b"), names=DOCKERFILE_NAMES),
    Rule("CONFIG-DOCKER-NO-USER", "Dockerfile runs as root", "medium", "config",
         "No USER instruction found; the container runs as root by default",
         re.compile(r"(?im)^\s*USER\s+"), names=DOCKERFILE_NAMES),
    Rule("CONFIG-DOCKER-ADD-REMOTE", "Dockerfile ADD from a remote URL", "medium", "config",
         "ADD with a URL skips layer caching and build-time verification; prefer curl/COPY",
         re.compile(r"(?im)^\s*ADD\s+https?://"), names=DOCKERFILE_NAMES),
    Rule("CONFIG-COMPOSE-PRIVILEGED", "docker-compose service runs privileged", "high", "config",
         "privileged: true gives the container full access to the host",
         re.compile(r"(?i)\bprivileged\s*:\s*true\b"), names=COMPOSE_NAMES),
    Rule("CONFIG-COMPOSE-HOST-NETWORK", "docker-compose service uses host networking", "medium", "config",
         "network_mode: host removes network isolation from the container",
         re.compile(r"(?i)\bnetwork_mode\s*:\s*[\"']?host[\"']?"), names=COMPOSE_NAMES),
    Rule("CONFIG-COMPOSE-DOCKER-SOCK", "Docker socket mounted into a container", "high", "config",
         "Mounting /var/run/docker.sock grants the container control over the host's Docker daemon",
         re.compile(r"/var/run/docker\.sock"), names=COMPOSE_NAMES),
    Rule("CONFIG-CORS-WILDCARD", "CORS allows any origin", "medium", "config",
         "A wildcard CORS origin allows any website to call this API with credentials",
         re.compile(r"(?i)Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']\*[\"']|"
                    r"\borigins?\s*=\s*[\"']\*[\"']|CORS\([^)]*origins?\s*=\s*[\"']\*[\"']")),
]

# Config rules where the finding means "this instruction is absent from the
# whole file" are checked once per file rather than per matching line.
CONFIG_WHOLE_FILE_ABSENCE = {"CONFIG-DOCKER-NO-USER"}

# --------------------------------------------------------------------------
# Dependency hygiene (version pinning in manifests)
# --------------------------------------------------------------------------
DEPENDENCY_UNPINNED = Rule(
    "DEPENDENCY-UNPINNED-VERSION", "Unpinned dependency version", "low", "dependency",
    "No version constraint; a future release could introduce breaking or malicious changes")
DEPENDENCY_WILDCARD = Rule(
    "DEPENDENCY-WILDCARD-VERSION", "Wildcard/latest dependency version", "medium", "dependency",
    "A '*' or 'latest' version accepts any future release, including compromised ones")
DEPENDENCY_RULES = [DEPENDENCY_UNPINNED, DEPENDENCY_WILDCARD]

# --------------------------------------------------------------------------
# Licenses. Order matters: AGPL and LGPL texts reference the GPL, so they
# must be tested first.
# --------------------------------------------------------------------------
def _lic(name, title, severity, text_re, spdx_re):
    return Rule("LICENSE-" + name, title, severity, "license",
                title + " license detected; review commercial compatibility",
                re.compile(text_re, re.I), re.compile(spdx_re, re.I))


LICENSE_RULES = [
    _lic("AGPL", "GNU AGPL", "critical", r"GNU AFFERO GENERAL PUBLIC LICENSE", r"^AGPL"),
    _lic("SSPL", "Server Side Public License", "critical", r"SERVER SIDE PUBLIC LICENSE", r"^SSPL"),
    _lic("LGPL", "GNU LGPL", "medium", r"GNU LESSER GENERAL PUBLIC LICENSE", r"^LGPL"),
    _lic("GPL", "GNU GPL", "high", r"GNU GENERAL PUBLIC LICENSE", r"^GPL"),
    _lic("EUPL", "European Union Public Licence", "medium", r"EUROPEAN UNION PUBLIC LICEN[CS]E", r"^EUPL"),
    _lic("BUSL", "Business Source License", "high", r"BUSINESS SOURCE LICENSE", r"^BUSL"),
    _lic("CC-BY-NC", "Creative Commons NonCommercial", "high", r"CREATIVE COMMONS.{0,80}NONCOMMERCIAL", r"^CC-BY-NC"),
]

LICENSE_FILENAMES = ("license", "licence", "copying", "unlicense")
SPDX_HEADER = re.compile(r"SPDX-License-Identifier:\s*([^\r\n]+)")
LICENSE_TEXT_WINDOW = 1500  # only the start of a license file is classified


def classify_text(text: str):
    """Return the first license rule whose title appears near the top of `text`."""
    head = text[:LICENSE_TEXT_WINDOW]
    for rule in LICENSE_RULES:
        if rule.pattern.search(head):
            return rule
    return None


def classify_spdx(expression: str) -> List[Rule]:
    """Return license rules matching any token of an SPDX id or expression."""
    hits: List[Rule] = []
    for token in re.findall(r"[A-Za-z0-9.\-+]+", expression):
        for rule in LICENSE_RULES:
            if rule.spdx.search(token):
                if rule not in hits:
                    hits.append(rule)
                break
    return hits


def all_rules() -> List[Rule]:
    return (list(SECRET_RULES) + SENSITIVE_FILE_RULES + list(VULN_RULES) + list(LICENSE_RULES)
            + list(CONFIG_RULES) + list(DEPENDENCY_RULES))
