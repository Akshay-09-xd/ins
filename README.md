# Dynamic One-Time-Password Authentication with Expiry and Single-Use Verification

BIS703 Information & Network Security, activity-based learning project (Module 3: entity authentication, freshness, dynamic password schemes).

## What it does

A PIN-protected software token and an authentication server share a 256-bit secret `K`. For each login the server issues a fresh random challenge with a sequence number and an expiry time. The token computes `OTP = Truncate(HMAC-SHA256(K, challenge || counter || expiry))`, a 6-digit code. The server accepts it only if it is

* **fresh**: submitted before the expiry time (default 60 s),
* **unused**: each challenge or OTP is deleted after one successful use, so replays fail,
* **correct**: compared in constant time against a salted SHA-256 hash (the plain OTP is never stored),
* **within the attempt limit**: 3 wrong guesses revoke the challenge, and 5 failures lock the account for 300 s.

A time-based mode (TOTP, RFC 6238) is included as well. It allows ±1 time-step of clock drift and refuses any step that has already been used.

## Layout

```
src/otp_auth.py          core library (HOTP/TOTP, OTPToken, AuthServer)
src/demo.py              scripted demo of 9 scenarios, plus an --interactive mode
tests/test_otp_auth.py   19 unit tests
output/                  captured demo and test output
report/                  implementation report (.docx) and its figures
```

## Run (Python 3.9+, standard library only)

```bash
cd src
python demo.py                 # scripted walk-through
python demo.py --interactive   # try it yourself (real clock)
cd ..
python -m unittest discover -s tests -v
```
