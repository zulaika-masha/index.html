# Cyber Guard — Web Security & Threat Protection

**Cyber Guard** is a web-based cybersecurity toolkit built with **Python**, **Flask**, **HTML5**, **CSS3**, and **JavaScript**.

## Features

1. **Scam URL Scanner (`/scan`)**
   - Evaluates HTTP vs. HTTPS protocols, raw IP hosts, phishing keywords, unusually long URLs, excessive subdomains, URL shorteners, and suspicious symbols/encoding.
   - Outputs a 0–100 risk score, 7-point inspection summary, and classification (`No Obvious Warning Signs`, `Needs Verification`, `Suspicious`).
2. **Password Strength Checker**
   - 100% client-side evaluation of length, character variety, entropy, estimated brute-force resistance, and common sequential/dictionary patterns.
   - Includes a cryptographically random 16-character password generator and copy helper.
3. **Cyber Safety Quiz**
   - 6 interactive scenario-based questions covering phishing links, URL shorteners, HTTPS myths, password hygiene, `@` URL obfuscation, and out-of-band verification.
4. **Cyber Crime Awareness & Official Reporting**
   - Direct link to India's National Cyber Crime Reporting Portal (`https://cybercrime.gov.in/`), helpline `1930` guidance, common cyber crime categories, and immediate incident response steps.

## How to Run Locally

```bash
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

To run the unit tests:

```bash
python -m unittest discover -s tests -v
```

## Deploy to Vercel

This project includes `api/index.py`, `vercel.json`, and `requirements.txt` for Vercel deployment.

1. Upload or push the `cyber-guard` folder to a **GitHub** repository.
2. Go to [vercel.com](https://vercel.com), click **Add New → Project**, and import your repository.
3. Keep the root directory and click **Deploy** (Vercel uses `vercel.json` + `api/index.py` + `requirements.txt`).
