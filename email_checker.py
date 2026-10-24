"""Phishing email checker for Sprint A. Uses made-up emails only.

Run:  python email_checker.py
It checks four sample emails, then lets you paste your own.
"""
import re

TRUSTED = ["vegabrooksdental.example", "dentalsupplyco.example"]
URGENT = ["act now", "immediately", "within 24 hours", "urgent", "overdue",
          "account locked", "final notice", "suspended"]
PAYMENT = ["pay now", "payment due", "wire transfer", "send payment", "gift card"]
LOGIN = ["password", "sign in", "log in", "verify your account"]

SAMPLES = [
    ("Fake overdue invoice", """From: billing@dentalsuppIy-co.example
Subject: Invoice #4471 overdue
Your invoice is overdue. Pay now to avoid a late fee. Reply immediately."""),
    ("Fake storage warning", """From: it-support@vegabrooksdental-help.example
Subject: Your mailbox is full
Sign in within 24 hours or you will lose access.
[https://mail.vegabrooksdental.example/storage](http://storage-fix.example.net/login)"""),
    ("Normal appointment reminder", """From: reception@vegabrooksdental.example
Subject: Appointment reminder
Hi, this is a reminder that your appointment is tomorrow at 10 AM."""),
    ("Vague attachment", """From: j.miller@docs-share.example
Subject: Document
Please review the attached document."""),
]


def similarity(a, b):
    """Return 0 to 1 for how alike two strings are (edit distance based)."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return 1 - prev[-1] / max(len(a), len(b), 1)


def host(text):
    m = re.search(r"(?:https?://)?([\w.-]+\.[a-z]{2,})", text, re.I)
    return m.group(1).lower() if m else ""


def check_email(text):
    """Return (verdict, reasons) for one email."""
    low = text.lower()
    reasons = []

    m = re.search(r"^from:.*?[\w.+-]+@([\w.-]+\.[a-z]+)", text, re.I | re.M)
    domain = m.group(1).lower() if m else ""
    known = domain in TRUSTED
    lookalike = (not known) and any(similarity(domain, t) >= 0.7 for t in TRUSTED)
    has_attachment = "attach" in low

    if lookalike:
        reasons.append("The sender address looks almost like a real one but is not.")
    if any(w in low for w in URGENT):
        reasons.append("It uses urgent wording to rush you.")
    if any(w in low for w in PAYMENT):
        reasons.append("It asks for a payment.")
    if any(w in low for w in LOGIN):
        reasons.append("It asks you to sign in or give a password.")
    for label, url in re.findall(r"\[([^\]]+)\]\((https?://[^)\s]+)\)", text):
        if host(label) and host(label) != host(url):
            reasons.append("A link goes somewhere different than it says.")
            break
    if has_attachment and domain and not known and not lookalike:
        reasons.append("An unknown sender included an attachment.")

    n = len(reasons)
    verdict = "SAFE" if n == 0 else "UNSURE" if n <= 2 else "SUSPICIOUS"
    return verdict, reasons


def show(name, text, results):
    verdict, reasons = check_email(text)
    results.append(verdict)
    print(f"\n{name}: {verdict}")
    for r in reasons or ["No warning signs found."]:
        print(f"  - {r}")


def summary(results):
    flagged = sum(v != "SAFE" for v in results)
    print(f"\nSummary: {len(results)} emails checked, {flagged} flagged "
          f"({results.count('SUSPICIOUS')} suspicious, {results.count('UNSURE')} unsure).")


if __name__ == "__main__":
    results = []
    for name, text in SAMPLES:
        show(name, text, results)
    summary(results)

    print("\nPaste your own made-up email. Type END on its own line to check it.")
    while True:
        lines = []
        try:
            while (line := input()) != "END":
                lines.append(line)
        except EOFError:
            break
        if not lines:
            break
        show("Your email", "\n".join(lines), results)
        summary(results)
        print("\nPaste another, or press Enter then END to quit.")
