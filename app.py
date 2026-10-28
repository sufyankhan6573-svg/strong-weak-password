"""Password Strength Checker - Streamlit app (weak vs strong passwords).

What it does
  * Scores a password 0-100 and labels it Very weak ... Very strong
  * Explains WHY: common password, leetspeak tricks, repeats, sequences, keyboard walks, years
  * Estimates crack time (offline attack vs online attack)
  * Optional breach check using HaveIBeenPwned's k-anonymity API (only a 5-character hash prefix leaves your device)
  * Generates strong random passwords with Python's `secrets` module
  * Optional AI coach (Gemini Flash) that sees ONLY an anonymous summary - never the password itself

Privacy design: the password is analysed locally. It is never sent to Gemini and never stored.
"""

import hashlib
import math
import os
import re
import secrets
import string
import urllib.request

DEFAULT_MODEL = "gemini-3.6-flash"  # override with env var / secret GEMINI_MODEL

OFFLINE_GUESSES_PER_SEC = 1e10  # fast-hash offline attack on a GPU rig (pessimistic, realistic)
ONLINE_GUESSES_PER_HOUR = 100  # throttled login form

# A small built-in list of very common passwords (real attackers use lists with millions of entries).
COMMON_PASSWORDS = set(
    """
password password1 password12 password123 passw0rd p@ssw0rd p@ssword 123456 1234567 12345678 123456789
1234567890 12345 1234 111111 000000 123123 654321 666666 121212 112233 7777777 987654321 qwerty qwerty123
qwertyuiop qwerty1 1q2w3e4r 1q2w3e 1qaz2wsx zaq12wsx asdfgh asdfghjkl zxcvbnm abc123 abcd1234 abcdef
iloveyou iloveyou1 princess sunshine monkey dragon football baseball basketball soccer hockey master
shadow superman batman spiderman starwars pokemon naruto minecraft whatever freedom trustno1 letmein
welcome welcome1 welcome123 login admin admin123 administrator root toor guest user test test123 testing
changeme default secret qazwsx hello hello123 hello1 michael jennifer jessica charlie daniel thomas
jordan hunter ranger buster cookie summer winter spring autumn flower ginger pepper mustang ferrari
harley liverpool chelsea arsenal manchester barcelona realmadrid cricket pakistan india islamabad
peshawar lahore karachi allah muhammad ali123 khan123 love lovely lover angel angel123 baby babygirl
fuckyou google facebook instagram snapchat whatsapp youtube
""".split()
)

LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "0": "o", "5": "s", "$": "s", "7": "t", "!": "i", "+": "t"})

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "qazwsxedcrfv"]


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
def char_pool_size(pw: str) -> int:
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"\d", pw):
        pool += 10
    if re.search(r"[ !\"#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~]", pw):
        pool += 33
    if re.search(r"[^\x00-\x7f]", pw):
        pool += 20
    return pool


def char_classes(pw: str) -> dict:
    return {
        "lowercase": bool(re.search(r"[a-z]", pw)),
        "uppercase": bool(re.search(r"[A-Z]", pw)),
        "digits": bool(re.search(r"\d", pw)),
        "symbols": bool(re.search(r"[^A-Za-z0-9]", pw)),
    }


def find_repeats(pw: str):
    """Runs of the same character, length >= 3 -> list of (start, length)."""
    return [(m.start(), len(m.group())) for m in re.finditer(r"(.)\1{2,}", pw)]


def find_sequences(pw: str):
    """Runs of consecutive ascending/descending letters or digits, length >= 3 (abc, 4321)."""
    out, i, n = [], 0, len(pw)
    while i < n - 2:
        step = ord(pw[i + 1]) - ord(pw[i])
        same_kind = pw[i].isalnum() and pw[i + 1].isalnum() and (pw[i].isdigit() == pw[i + 1].isdigit())
        if step in (1, -1) and same_kind:
            j = i + 1
            while (
                j + 1 < n
                and pw[j + 1].isalnum()
                and (pw[j + 1].isdigit() == pw[j].isdigit())
                and ord(pw[j + 1]) - ord(pw[j]) == step
            ):
                j += 1
            if j - i + 1 >= 3:
                out.append((i, j - i + 1))
                i = j
                continue
        i += 1
    return out


def find_keyboard_walks(pw: str):
    """Runs of >= 4 neighbouring keys on a keyboard row (qwer, asdf, 1234), either direction."""
    low, out = pw.lower(), []
    for row in KEYBOARD_ROWS:
        for line in (row, row[::-1]):
            for size in range(len(line), 3, -1):
                for s in range(len(line) - size + 1):
                    chunk = line[s : s + size]
                    idx = low.find(chunk)
                    if idx != -1 and not any(idx < a + b and a < idx + size for a, b in out):
                        out.append((idx, size))
    return out


def find_years(pw: str):
    return [(m.start(), 4) for m in re.finditer(r"(?:19|20)\d{2}", pw)]


def common_match(pw: str):
    """Return 'exact', 'base' or None. Handles case, leetspeak and trailing digits/symbols."""
    low = pw.lower()
    leet = low.translate(LEET)
    leet_variants = {leet, leet.replace("1", "l"), leet.replace("1", "i")}
    candidates = {low} | leet_variants
    if any(c in COMMON_PASSWORDS for c in candidates):
        return "exact"
    for c in candidates:
        base = re.sub(r"[\d\W_]+$", "", c)  # strip trailing digits/symbols: 'Dragon2024!' -> 'dragon'
        if len(base) >= 4 and base in COMMON_PASSWORDS:
            return "base"
    return None


WORD_BITS = 17.0  # roughly log2(~130k dictionary words)
SUFFIX_BITS_PER_CHAR = 5.4  # a trailing digit/symbol is one of ~43 likely characters


def word_plus_suffix(pw: str):
    """Detect 'Word' / 'word' (4-12 letters) followed by up to 6 digits/symbols, e.g. Elephant@2024.

    Random strings rarely look like a lowercase or Capitalised word, so this catches the most common
    human pattern. It is conservative: a random all-lowercase string of the same shape is also flagged.
    """
    m = re.fullmatch(r"([A-Za-z][a-z]{3,11})([\d\W_]{0,6})", pw)
    return (m.group(1), m.group(2)) if m else None


def analyze(pw: str, assume_random: bool = False) -> dict:
    """Pure, deterministic local analysis. Never makes a network call.

    assume_random=True skips the human-pattern heuristics (used for passwords this app generated itself).
    """
    n = len(pw)
    classes = char_classes(pw)
    pool = char_pool_size(pw)
    findings = []
    issues = []  # generic problem codes; safe to share with the AI coach (contain no password text)

    free = set()  # positions whose character is predictable (adds no entropy)
    for start, length in find_repeats(pw):
        free.update(range(start + 1, start + length))
        findings.append(f"Repeated characters ('{pw[start:start + min(length, 4)]}...')")
        issues.append("repeated_characters")
    for start, length in find_sequences(pw):
        free.update(range(start + 1, start + length))
        findings.append(f"Sequence '{pw[start:start + length]}' is easy to guess")
        issues.append("sequence")
    for start, length in find_keyboard_walks(pw):
        free.update(range(start + 1, start + length))
        findings.append(f"Keyboard pattern '{pw[start:start + length]}'")
        issues.append("keyboard_pattern")
    for start, _ in find_years(pw):
        free.update((start, start + 1))
        findings.append(f"Contains a year ('{pw[start:start + 4]}'), a favourite of attackers")
        issues.append("contains_year")

    # Look-alike swaps inside a word (Tr0ub4dor): each swap adds almost no real entropy.
    swaps = [
        i for i in range(1, n - 1)
        if pw[i] in "0345@$7" and pw[i - 1].isalpha() and pw[i + 1].isalpha()
    ]
    if len(swaps) >= 2:
        free.update(swaps)
        findings.append("Looks like letters swapped for look-alike digits/symbols (e.g. 0 for o), which attackers try automatically")

    bits_per_char = math.log2(pool) if pool else 0.0
    naive_bits = n * bits_per_char
    bits = max(0, n - len(free)) * bits_per_char

    # Passphrases of real words: strength comes from the NUMBER of words (~12 bits each for a
    # large dictionary), not from the letter count.
    words = [w for w in re.split(r"[\s\-_.]+", pw) if w]
    if len(words) >= 3 and all(w.isalpha() and 1 <= len(w) <= 12 for w in words):
        word_bits = len(words) * 12.0
        if word_bits < bits:
            bits = word_bits
        findings.append(f"Looks like a {len(words)}-word passphrase, so strength is counted per word (about 12 bits each), not per letter")

    match = common_match(pw) if n else None
    if match == "exact":
        bits = min(bits, 10.0)
        findings.insert(0, "This is (or is a trivial variation of) a very common password")
        issues.append("common_password")
    elif match == "base":
        bits = min(bits, 22.0)
        findings.insert(0, "Built on a common password with digits/symbols added, which attackers try first")
        issues.append("common_password_with_suffix")
    elif not assume_random:
        word = word_plus_suffix(pw)
        if word is not None:
            suffix_len = len(word[1])
            suffix_bits = suffix_len * SUFFIX_BITS_PER_CHAR
            if re.search(r"(?:19|20)\d{2}", word[1]):  # a year is only ~7 bits, not 4 free characters
                suffix_bits -= 4 * SUFFIX_BITS_PER_CHAR - 7.0
            bits = min(bits, WORD_BITS + suffix_bits)
            findings.insert(0, "Looks like a single dictionary-style word with a few digits/symbols added")
            issues.append("single_word_plus_suffix")

    if n and len(set(pw)) == 1:
        bits = min(bits, 4.0)
    if 0 < n < 8:
        findings.append("Shorter than 8 characters")
        issues.append("too_short")
    elif 8 <= n < 12:
        findings.append("Under 12 characters; aim for 12-16 or more")
        issues.append("under_12_characters")
    if n and sum(classes.values()) == 1:
        findings.append("Uses only one type of character")
        issues.append("single_character_type")

    return {
        "length": n,
        "classes": classes,
        "pool": pool,
        "naive_bits": round(naive_bits, 1),
        "bits": round(bits, 1),
        "common": match,
        "findings": findings,
        "issues": issues,
        "breach_count": None,  # filled in later if the user opts in to the breach check
    }


def score_and_label(analysis: dict):
    """Return (score 0-100, label, colour). A known breach caps the result."""
    if analysis["length"] == 0:
        return 0, "Empty", "gray"
    bits = analysis["bits"]
    score = min(100, round(bits * 100 / 80))
    if bits < 28:
        label, color = "Very weak", "red"
    elif bits < 40:
        label, color = "Weak", "red"
    elif bits < 60:
        label, color = "Fair", "orange"
    elif bits < 80:
        label, color = "Strong", "green"
    else:
        label, color = "Very strong", "green"
    if analysis.get("breach_count"):
        score, label, color = min(score, 10), "Compromised (found in data breaches)", "red"
    return score, label, color


def humanize_seconds(seconds: float) -> str:
    if seconds < 1:
        return "instantly (under a second)"
    units = [("second", 1), ("minute", 60), ("hour", 3600), ("day", 86400), ("year", 31_557_600)]
    if seconds >= 31_557_600 * 1_000_000_000:
        return "billions of years or more"
    if seconds >= 31_557_600 * 1_000_000:
        return f"{seconds / 31_557_600 / 1_000_000:,.0f} million years"
    if seconds >= 31_557_600 * 100:
        return f"{seconds / 31_557_600:,.0f} years"
    for name, size in reversed(units):
        if seconds >= size:
            v = seconds / size
            v = round(v)
            return f"about {v:,} {name}{'' if v == 1 else 's'}"
    return "instantly"


def crack_times(bits: float) -> dict:
    """Average time to guess = half the search space. Estimates, not guarantees."""
    avg_guesses = (2 ** min(bits, 400)) / 2
    return {
        "offline": humanize_seconds(avg_guesses / OFFLINE_GUESSES_PER_SEC),
        "online": humanize_seconds(avg_guesses / (ONLINE_GUESSES_PER_HOUR / 3600)),
    }


def suggestions(analysis: dict) -> list:
    n, tips = analysis["length"], []
    if n == 0:
        return tips
    if analysis.get("breach_count"):
        tips.append("Stop using this password everywhere and change it now; it has appeared in real data breaches.")
    if "single_word_plus_suffix" in analysis["issues"]:
        tips.append("A word with a number or symbol on the end is one of the first patterns attackers try. Use random characters or several unrelated words.")
    if analysis["common"]:
        tips.append("Avoid common words and simple tricks like 'a'->'@'. Attackers try those substitutions automatically.")
    if n < 12:
        tips.append("Make it at least 12-16 characters. Length matters more than complexity.")
    if any(i in analysis["issues"] for i in ("sequence", "keyboard_pattern", "repeated_characters")):
        tips.append("Remove sequences, keyboard patterns and repeated characters.")
    if "contains_year" in analysis["issues"]:
        tips.append("Don't use birth years or the current year.")
    if sum(analysis["classes"].values()) < 3 and n < 16:
        tips.append("Mix lowercase, uppercase, digits and symbols, or use a long random passphrase.")
    tips.append("Use a unique password for every account and store them in a password manager; turn on 2-factor authentication.")
    return tips


# --------------------------------------------------------------------------- #
# Optional breach check (HaveIBeenPwned k-anonymity)
# --------------------------------------------------------------------------- #
def _fetch_range(prefix: str) -> str:
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "password-strength-checker", "Add-Padding": "true"},
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        return resp.read().decode("utf-8")


def parse_range_response(body: str, suffix: str) -> int:
    """Find our hash suffix in the API response and return its breach count (0 if absent)."""
    for line in body.splitlines():
        part, _, count = line.strip().partition(":")
        if part.upper() == suffix.upper():
            try:
                return int(count)
            except ValueError:
                return 0  # padded entries
    return 0


def breach_count(pw: str, fetch=_fetch_range) -> int:
    """Only the first 5 hex chars of the SHA-1 hash are sent; the full password/hash never leaves the device."""
    digest = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()  # nosec - required by the HIBP API
    return parse_range_response(fetch(digest[:5]), digest[5:])


# --------------------------------------------------------------------------- #
# Password generator
# --------------------------------------------------------------------------- #
def generate_password(length=16, lower=True, upper=True, digits=True, symbols=True) -> str:
    pools = []
    if lower:
        pools.append(string.ascii_lowercase)
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?")
    if not pools:
        raise ValueError("Select at least one character type.")
    if not 8 <= length <= 128:
        raise ValueError("Length must be between 8 and 128.")
    chars = [secrets.choice(p) for p in pools]  # guarantee one of each selected type
    allchars = "".join(pools)
    chars += [secrets.choice(allchars) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# --------------------------------------------------------------------------- #
# Optional AI coach - sees an anonymous summary, never the password
# --------------------------------------------------------------------------- #
def build_ai_summary(analysis: dict, score: int, label: str) -> dict:
    return {
        "length": analysis["length"],
        "character_types_used": [k for k, v in analysis["classes"].items() if v],
        "estimated_entropy_bits": analysis["bits"],
        "score_out_of_100": score,
        "label": label,
        "is_common_password": analysis["common"] is not None,
        "found_in_breaches": bool(analysis.get("breach_count")),
        "problem_codes": analysis["issues"],  # generic codes only; no password text
    }


def build_ai_prompt(summary: dict) -> str:
    import json

    return f"""You are a friendly cybersecurity teacher. A password was analysed locally. You are given ONLY an
anonymous summary; you do NOT know the password and must never ask for it.

SUMMARY (JSON):
{json.dumps(summary, indent=2)}

In plain language write:
1. A 2-sentence verdict.
2. Exactly 4 short, practical tips tailored to the problem codes (use a bullet list).
3. One sentence on why length and uniqueness beat clever substitutions.
Be honest: do not call a weak password strong. No markdown headings."""


def call_gemini(api_key: str, model: str, prompt: str) -> str:
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=api_key)
    config = types.GenerateContentConfig(temperature=0.4)
    return client.models.generate_content(model=model, contents=prompt, config=config).text or ""


def friendly_api_error(exc: Exception) -> str:
    low = str(exc).lower()
    if "api key" in low or "api_key" in low or "permission" in low or "401" in low or "403" in low:
        return "The Gemini API key was rejected. Check that it is correct and active."
    if "429" in low or "quota" in low or "resource_exhausted" in low:
        return "Gemini rate/quota limit reached. Wait a minute and try again."
    if "404" in low or "not found" in low:
        return "The model name was not found. Set GEMINI_MODEL to a valid Gemini Flash model."
    return f"Something went wrong while contacting Gemini: {exc}"


# --------------------------------------------------------------------------- #
# Streamlit UI
# --------------------------------------------------------------------------- #
def get_secret(name: str):
    import streamlit as st

    try:
        if name in st.secrets:
            return st.secrets[name]
    except Exception:
        pass
    return os.environ.get(name)


def main():
    import streamlit as st

    st.set_page_config(page_title="Password Strength Checker", page_icon="🔐", layout="centered")
    st.title("🔐 Password Strength Checker")
    st.caption("Find out whether a password is weak or strong, and why. Analysis runs locally; nothing is stored.")

    api_key = get_secret("GEMINI_API_KEY")
    model = get_secret("GEMINI_MODEL") or DEFAULT_MODEL
    with st.sidebar:
        st.header("Settings")
        use_breach = st.checkbox(
            "Check known data breaches",
            value=False,
            help="Sends only the first 5 characters of the password's SHA-1 hash to haveibeenpwned.com. "
            "The password itself is never sent.",
        )
        if not api_key:
            api_key = st.text_input("Gemini API key (optional, for AI coach)", type="password")
        else:
            st.success("API key loaded from secrets.")
        model = st.text_input("Model", value=model)
        st.caption("The AI coach only receives an anonymous summary, never your password.")

    tab_check, tab_gen = st.tabs(["🔎 Check a password", "🎲 Generate a strong password"])

    with tab_check:
        st.warning("Don't type a password you use for real accounts into any website you don't trust. Test similar ones.")
        pw = st.text_input("Password", type="password", key="pw_input")
        if pw:
            analysis = analyze(pw)
            if use_breach:
                try:
                    analysis["breach_count"] = breach_count(pw)
                except Exception:
                    st.info("Breach check unavailable right now (no internet or service down). Local analysis still applies.")
            score, label, color = score_and_label(analysis)
            c1, c2 = st.columns([1, 2])
            c1.metric("Score", f"{score}/100")
            c2.markdown(f"### :{color}[{label}]")
            st.progress(score / 100)

            if analysis.get("breach_count"):
                st.error(f"This password appears in data breaches {analysis['breach_count']:,} times. Never use it.")
            elif use_breach and analysis["breach_count"] == 0:
                st.success("Not found in the known breach database.")

            times = crack_times(analysis["bits"])
            st.subheader("Estimated time to crack")
            t1, t2 = st.columns(2)
            t1.metric("Offline attack", times["offline"])
            t2.metric("Online attack", times["online"])
            st.caption(
                f"Offline = 10 billion guesses/second against a stolen hash. Online = {ONLINE_GUESSES_PER_HOUR} guesses/hour "
                f"against a login form. Effective strength: {analysis['bits']} bits (a naive count would say {analysis['naive_bits']})."
            )

            st.subheader("Checks")
            cols = st.columns(4)
            for col, (name, ok) in zip(cols, analysis["classes"].items()):
                col.write(f"{'✅' if ok else '❌'} {name}")
            st.write(f"{'✅' if analysis['length'] >= 12 else '❌'} Length: {analysis['length']} (12+ recommended)")

            if analysis["findings"]:
                st.subheader("Problems found")
                for f in analysis["findings"]:
                    st.write(f"- ⚠️ {f}")
            tips = suggestions(analysis)
            if tips:
                st.subheader("How to improve")
                for t in tips:
                    st.write(f"- {t}")

            if st.button("🤖 Ask AI coach for advice"):
                if not api_key:
                    st.error("Add a Gemini API key in the sidebar to use the AI coach.")
                else:
                    prompt = build_ai_prompt(build_ai_summary(analysis, score, label))
                    with st.spinner("Thinking..."):
                        try:
                            st.write(call_gemini(api_key, model, prompt))
                        except Exception as exc:
                            st.error(friendly_api_error(exc))

    with tab_gen:
        length = st.slider("Length", 8, 64, 16)
        g1, g2, g3, g4 = st.columns(4)
        lower = g1.checkbox("a-z", True)
        upper = g2.checkbox("A-Z", True)
        digits = g3.checkbox("0-9", True)
        symbols = g4.checkbox("!@#", True)
        if st.button("Generate", type="primary"):
            try:
                st.session_state["generated"] = generate_password(length, lower, upper, digits, symbols)
            except ValueError as exc:
                st.error(str(exc))
        if "generated" in st.session_state:
            new_pw = st.session_state["generated"]
            st.code(new_pw, language=None)
            a = analyze(new_pw, assume_random=True)
            score, label, _ = score_and_label(a)
            st.caption(f"Strength: {label} ({score}/100), about {a['bits']} bits. Save it in a password manager.")


if __name__ == "__main__":
    main()
