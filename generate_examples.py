#!/usr/bin/env python3
"""Generate examples.txt by running the guard on sample prompts.

The sample prompts use well-known example values (the AWS example key,
the Stripe test card) so nothing real is ever printed.
"""
import subprocess
import sys

SAMPLES = [
    ("1. Clean prompt (SAFE)",
     "Explain how a TLS handshake works, in plain language for first-year students."),
    ("2. Leaked AWS key + internal server (BLOCK)",
     "My deploy failed with key AKIAIOSFODNN7EXAMPLE on server 192.168.1.10, can you debug it?"),
    ("3. Password pasted into a support question (BLOCK)",
     "Login keeps failing with password=hunter2 for the admin account, what should I check?"),
    ("4. Email only (REVIEW)",
     "Please email the lab notes to student@example.com before Monday's class."),
    ("5. Test card number (BLOCK, Luhn-valid)",
     "The payment for card 4242 4242 4242 4242 was declined, why?"),
    ("6. Random digits are NOT a card (SAFE)",
     "Order 1234 5678 9012 3456 shipped today, track it please."),
]

lines = []
for title, prompt in SAMPLES:
    proc = subprocess.run([sys.executable, "ai_prompt_guard.py", prompt],
                          capture_output=True, text=True, cwd=__file__.rsplit("/", 1)[0])
    lines.append(title)
    lines.append("Prompt: " + prompt)
    lines.append(proc.stdout.rstrip())
    lines.append("")

with open(__file__.rsplit("/", 1)[0] + "/examples.txt", "w", encoding="utf-8") as handle:
    handle.write("\n".join(lines))
print("wrote examples.txt")
