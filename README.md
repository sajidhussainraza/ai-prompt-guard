# AI Prompt Guard

A small, dependency-free Python CLI tool (standard library only) that
scans a prompt for secrets and personal data *before* it is sent to an
LLM, and produces a redacted version that is safe to send.

The scan runs entirely locally, so the very text you are worried about
leaking never leaves your machine to be checked. It is the habit this
tool teaches: check the prompt the same way you would check code before
a commit.

## Run it

```bash
# Scan prompt text (exit code 2 means BLOCK)
python3 ai_prompt_guard.py "My deploy failed, can you debug it?"

# Pipe a prompt in
echo "Contact student@example.com about the lab" | python3 ai_prompt_guard.py

# Scan a saved prompt
python3 ai_prompt_guard.py --file prompt.txt

# Print only the redacted prompt, for piping into your LLM chat
python3 ai_prompt_guard.py --file prompt.txt --sanitize

# Machine-readable output for scripts and lab reports
python3 ai_prompt_guard.py "text" --json
```

## What it checks

| Finding | Severity | Verdict effect |
|---------|----------|----------------|
| AWS access key, GitHub/Slack token, private key block, bearer token, JWT, password assignment, valid (Luhn-checked) card number | High | BLOCK: do not send the original |
| Generic API key, email address | Medium | REVIEW: check the redacted version |
| Phone number, private IP address, internal hostname (`.internal`, `.intranet`, `.local`, `.corp`, `.lan`) | Low | REVIEW: check the redacted version |

Verdicts: `SAFE` (nothing found), `REVIEW` (only medium/low findings),
`BLOCK` (at least one high-severity secret). The risk score is 40 per
high finding, 20 per medium, 10 per low, capped at 100.

Findings are reported by type with a masked preview (last digits only)
and concrete advice, e.g. rotate the key, revoke the token, replace a
real address with an example address. Overlapping matches resolve in
favour of the longest span, so a card number is not also reported as a
phone number, and a long digit string such as an order number is not
mistaken for a phone number.

## Example output

```text
Verdict: BLOCK  (risk score 50/100)
  - [HIGH] AWS access key: ...7
      Advice: Rotate this key and move it to a secrets manager; never paste keys into prompts.
  - [LOW] Private IP address: ...8110
      Advice: Internal addresses map your network for an attacker. Replace them with a placeholder.

Redacted version (safe to send):
My deploy failed with key [AWS-ACCESS-KEY] on server [PRIVATE-IP], can you debug it?
```

Six worked examples (clean, leaked key, pasted password, email only,
test card, random digits that are not a card) are in `examples.txt`,
generated offline by `generate_examples.py`. The sample prompts use
only well-known example values (the AWS documentation example key, the
Stripe test card), so nothing real is ever printed.

## Tests

```bash
python3 test_guard.py
```

15 self-check tests, all offline: clean prompt, each high-severity
secret type, email as REVIEW rather than BLOCK, Luhn-valid card vs.
random digits, private IP and internal hostname, multiple findings all
redacted, redaction preserving surrounding text, score capping at 100,
and findings never leaking the full secret in their preview. 15/15 pass.

## Limitations

Pattern matching catches the common shapes of secrets, not every
secret: a key in an unusual format, a secret split across lines, or
sensitive information phrased in plain words ("my mother's maiden
name is...") will slip through, and a redacted prompt can still leak
context. Treat a SAFE verdict as "no known pattern found", not as
proof that a prompt is safe, and never rely on redaction as a reason
to paste a live credential anywhere. If a real secret was ever pasted
into a chat, rotate or revoke it: redaction protects the next prompt,
not the one already sent.
