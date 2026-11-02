#!/usr/bin/env python3
"""AI Prompt Guard: scan a prompt for secrets and personal data before
it is sent to an LLM, and produce a redacted, safe-to-send version.

Standard library only. Nothing is sent anywhere: the scan runs locally,
so the very text you are worried about leaking never leaves your machine
to be checked.

Usage:
    python3 ai_prompt_guard.py "Summarise this log: ..."
    echo "My key is AKIA..." | python3 ai_prompt_guard.py
    python3 ai_prompt_guard.py --file prompt.txt --sanitize
    python3 ai_prompt_guard.py "text" --json

Verdicts:
    SAFE   - no findings; the prompt can go as-is.
    REVIEW - only low/medium personal-data findings; check the redacted
             version before sending.
    BLOCK  - at least one high-severity secret; do not send the original.
             Send the redacted version instead, or remove the secret.
"""

import argparse
import json
import re
import sys

# Each rule: (name, category, severity, regex, redaction label, advice)
RULES = [
    ("AWS access key", "secret", "high",
     r"\bAKIA[0-9A-Z]{16}\b", "[AWS-ACCESS-KEY]",
     "Rotate this key and move it to a secrets manager; never paste keys into prompts."),
    ("GitHub token", "secret", "high",
     r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b", "[GITHUB-TOKEN]",
     "Revoke this token in GitHub settings and issue a scoped replacement."),
    ("Slack token", "secret", "high",
     r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "[SLACK-TOKEN]",
     "Revoke this token in the Slack admin console."),
    ("Private key block", "secret", "high",
     r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", "[PRIVATE-KEY]",
     "A private key must never leave its host. Rotate the key pair if it was shared."),
    ("Bearer token", "secret", "high",
     r"\bBearer\s+[A-Za-z0-9\-._~+/=]{20,}", "[BEARER-TOKEN]",
     "Revoke the token and re-issue it; treat any pasted bearer token as compromised."),
    ("JWT", "secret", "high",
     r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[JWT]",
     "JWTs can carry identity claims. Do not paste live tokens into prompts."),
    ("Password assignment", "secret", "high",
     r"(?i)\b(?:password|passwd|pwd|secret)\s*[:=]\s*\S+", "[PASSWORD]",
     "Remove the password; describe the login problem instead of pasting credentials."),
    ("Generic API key", "secret", "medium",
     r"(?i)\b(?:api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*[\"']?[A-Za-z0-9\-_]{16,}[\"']?",
     "[API-KEY]",
     "Move the key to an environment variable or vault and paste only its last 4 characters if needed."),
    ("Credit card number", "pii", "high",
     r"\b(?:\d[ -]?){12,18}\d\b", "[CARD-NUMBER]",
     "Never paste card numbers into prompts. This match is only kept if it passes the Luhn check."),
    ("Email address", "pii", "medium",
     r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[EMAIL]",
     "Replace real addresses with an example address (e.g. user@example.com) before sending."),
    ("Phone number", "pii", "low",
     r"(?<!\d)(?:\+?\d{1,3}[- ]?)?(?:\d[- ]?){9,12}\d(?!\d)", "[PHONE]",
     "Strip phone numbers from logs and prompts unless the task genuinely needs one."),
    ("Private IP address", "internal", "low",
     r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
     "[PRIVATE-IP]",
     "Internal addresses map your network for an attacker. Replace them with a placeholder."),
    ("Internal hostname", "internal", "low",
     r"\b[A-Za-z0-9-]+\.(?:internal|intranet|local|corp|lan)\b", "[INTERNAL-HOST]",
     "Internal hostnames reveal infrastructure. Replace them with a generic name."),
]

SEVERITY_POINTS = {"high": 40, "medium": 20, "low": 10}


def _luhn_ok(candidate):
    """True if the digit string passes the Luhn checksum."""
    digits = [int(d) for d in re.sub(r"\D", "", candidate)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _mask(value, keep=4):
    """Show only the tail of a match, e.g. '...4242', for safe reporting."""
    tail = re.sub(r"\D", "", value)[-keep:] or value[-keep:]
    return "..." + tail


def _digit_run_length(text, start, end):
    """Digits in the maximal digit/space/dash run containing a span."""
    left = start
    while left > 0 and (text[left - 1].isdigit() or text[left - 1] in " -"):
        left -= 1
    right = end
    while right < len(text) and (text[right].isdigit() or text[right] in " -"):
        right += 1
    return sum(ch.isdigit() for ch in text[left:right])


def scan(text):
    """Return a list of findings, each a dict, in order of appearance.

    Overlapping matches are resolved in favour of the longest span
    (so a card number is not also reported as a phone number), and a
    phone candidate that is only part of a longer digit run (e.g. an
    order number) is dropped.
    """
    candidates = []
    for name, category, severity, pattern, label, advice in RULES:
        for match in re.finditer(pattern, text):
            value = match.group(0)
            if name == "Credit card number" and not _luhn_ok(value):
                continue
            if name == "Phone number" and re.search(r"[A-Za-z]", value):
                continue
            if name == "Phone number":
                digits = sum(ch.isdigit() for ch in value)
                if digits < 10 or digits > 15:
                    continue
                if digits != _digit_run_length(text, match.start(), match.end()):
                    continue
            candidates.append({
                "type": name,
                "category": category,
                "severity": severity,
                "span": [match.start(), match.end()],
                "preview": _mask(value),
                "redaction": label,
                "advice": advice,
                "pattern": pattern,
            })
    severity_rank = {"high": 0, "medium": 1, "low": 2}
    candidates.sort(key=lambda f: (f["span"][0],
                                   -(f["span"][1] - f["span"][0]),
                                   severity_rank[f["severity"]]))
    findings = []
    for candidate in candidates:
        start, end = candidate["span"]
        if any(start < kept["span"][1] and end > kept["span"][0] for kept in findings):
            continue
        findings.append(candidate)
    findings.sort(key=lambda f: f["span"][0])
    return findings


def sanitize(text, findings=None):
    """Return the text with every finding replaced by its redaction label."""
    if findings is None:
        findings = scan(text)
    # Replace from the end so earlier spans stay valid.
    out = text
    for finding in sorted(findings, key=lambda f: f["span"][0], reverse=True):
        start, end = finding["span"]
        out = out[:start] + finding["redaction"] + out[end:]
    return out


def risk_score(findings):
    """0-100 score: high findings dominate, capped at 100."""
    return min(100, sum(SEVERITY_POINTS[f["severity"]] for f in findings))


def verdict(findings):
    if any(f["severity"] == "high" for f in findings):
        return "BLOCK"
    if findings:
        return "REVIEW"
    return "SAFE"


def report(text):
    findings = scan(text)
    return {
        "verdict": verdict(findings),
        "score": risk_score(findings),
        "findings": findings,
        "sanitized": sanitize(text, findings),
    }


def _read_input(args):
    if args.file:
        with open(args.file, encoding="utf-8") as handle:
            return handle.read()
    if args.text:
        return " ".join(args.text)
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def main(argv=None):
    parser = argparse.ArgumentParser(description="Scan a prompt for secrets and personal data before sending it to an LLM.")
    parser.add_argument("text", nargs="*", help="Prompt text to scan (or pipe it on stdin).")
    parser.add_argument("--file", help="Read the prompt from a file.")
    parser.add_argument("--json", action="store_true", help="Machine-readable output.")
    parser.add_argument("--sanitize", action="store_true", help="Print only the redacted prompt.")
    args = parser.parse_args(argv)

    text = _read_input(args)
    if not text.strip():
        parser.error("no prompt supplied: pass text, --file, or pipe it on stdin")
    result = report(text)

    if args.sanitize:
        print(result["sanitized"])
        return 0 if result["verdict"] != "BLOCK" else 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Verdict: {result['verdict']}  (risk score {result['score']}/100)")
        if not result["findings"]:
            print("No secrets or personal data found. Safe to send.")
        else:
            for finding in result["findings"]:
                print(f"  - [{finding['severity'].upper()}] {finding['type']}: {finding['preview']}")
                print(f"      Advice: {finding['advice']}")
            print()
            print("Redacted version (safe to send):")
            print(result["sanitized"])
    return 0 if result["verdict"] != "BLOCK" else 2


if __name__ == "__main__":
    raise SystemExit(main())
