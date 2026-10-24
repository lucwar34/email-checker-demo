# Email Checker Demo

Capstone 1, Sprint A (Cybersecurity). A small checker that reads a made-up email and returns Looks safe, Unsure, or Suspicious with plain reasons. It never connects to a real inbox. All emails and names are made up.

## Run the Python version

    python email_checker.py

It checks four sample emails, prints a summary, then lets you paste your own (type END on its own line).

## Web version

Open `index.html`, or use the live page from GitHub Pages.

## Warning signs it checks

- Sender address that looks almost like a real one
- Urgent wording
- Requests for payment
- Requests to sign in or give a password
- Links that go somewhere different than they say
- Unknown sender with an attachment

No signs is safe, one or two is unsure, three or more is suspicious.
