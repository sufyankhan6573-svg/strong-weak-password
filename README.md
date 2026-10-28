# Password Strength Checker (Weak vs Strong)

A Streamlit app that tells you whether a password is weak or strong, and explains why.

- **Score 0-100** and a label: Very weak, Weak, Fair, Strong, Very strong
- **Why it's weak:** common passwords, look-alike swaps (`a` -> `@`), a single word plus digits, repeated characters, sequences (`abc`, `4321`), keyboard patterns (`qwerty`), years
- **Crack-time estimates** for an offline attack (stolen hash) and an online attack (login form)
- **Optional breach check** using the HaveIBeenPwned k-anonymity API. Only the first 5 characters of the password's SHA-1 hash are sent, never the password
- **Strong password generator** using Python's `secrets` module
- **Optional AI coach** (Gemini Flash). It receives only an anonymous summary (length, character types, score, generic problem codes). It never sees the password

## Files

| File | Purpose |
|------|---------|
| `app.py` | The Streamlit app |
| `requirements.txt` | Python dependencies |
| `README.md` | This file |

## Run locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

The checker and generator work with no API key. Only the AI coach needs one.

To use the AI coach, get a free key at https://aistudio.google.com/apikey and either paste it into the sidebar or set it:

```bash
export GEMINI_API_KEY="your-key"        # Windows PowerShell: $env:GEMINI_API_KEY="your-key"
```

## Configuration

| Name | Meaning | Default |
|------|---------|---------|
| `GEMINI_API_KEY` | Gemini API key for the AI coach (optional) | none |
| `GEMINI_MODEL` | Model ID to use | `gemini-3.6-flash` |

## Deploy on Streamlit Community Cloud

1. Push this repo to GitHub.
2. Go to https://share.streamlit.io and sign in with GitHub.
3. Click **Create app**, choose the repo, branch `main`, main file `app.py`.
4. (Optional, for the AI coach) Open **Advanced settings > Secrets** and add:

```toml
GEMINI_API_KEY = "your-key"
```

5. Click **Deploy**.

**Never commit your API key to GitHub.**

## How the score works

1. Estimate the size of the character pool (lowercase 26, uppercase 26, digits 10, symbols 33).
2. Entropy = length x log2(pool).
3. Subtract predictable characters (repeats, sequences, keyboard walks, years, look-alike swaps).
4. Cap the result for known weak shapes: very common passwords (10 bits), common password plus suffix (22 bits), single word plus a few digits/symbols (about 17 bits + about 5 bits per added character), word-based passphrases (12 bits per word).
5. Score = bits / 80, capped at 100. A password found in a data breach is capped at 10.

## Limits (please read)

- This is an **estimate**. The built-in list of common passwords is small (about 200 entries); real attackers use lists with millions. Anything the app rates "Fair" or better can still be weaker than shown if it is built from a dictionary word, a name or personal information.
- The "single word plus digits" rule is a human-pattern heuristic. It can wrongly flag a short random all-lowercase string. Passwords created by the built-in generator are exempt.
- Crack times assume 10 billion guesses per second offline and 100 per hour online. Real hardware and hashing algorithms vary a lot.
- The breach check needs an internet connection. If it fails, the local analysis still works.
- Best practice is not a clever password: use a unique, long, random password for every site in a password manager, and turn on 2-factor authentication.
- Don't type a real password into any website you don't trust. Test similar ones instead.
