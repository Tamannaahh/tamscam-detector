

# TamScam Detector – Fake Job Analyser

A web app that checks a job post and gives a **risk score (0–100)**, a verdict
(**Safe / Suspicious / High Risk**) and four **warning signs**.

## Features
- Candidate registration and login (strong password rule, hashed passwords)
- Scan a job post by typing it or uploading a PDF / DOCX / TXT file
- Warning signs: upfront fee, Telegram/WhatsApp contact, unrealistic fresher salary, free e-mail address
- Scan history for each user
- Admin dashboard: view users and scans, delete a scan or user, clear logs

## How it works
1. Text is turned into numbers with **TF-IDF** (12,000 features, 1–2 word phrases).
2. A **Linear SVM** gives a fake-chance (up to 75 points of the score).
3. Rule-based checks add extra points. Score ≥ 65 = High Risk, 35–64 = Suspicious, below 35 = Safe.

## Data and results
- 5 Kaggle datasets merged into **86,933 posts** (21.6% fake)
- Test set: 17,387 posts

| Model | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| Linear SVM | 91.81% | 99.20% | 62.62% | 76.78% |

High precision, moderate recall: the model is rarely wrong when it says "fake",
but it misses some fake posts. See the report for details and limitations.

## Tech stack
Python · Flask · Flask-SQLAlchemy · SQLite · scikit-learn · pandas · pypdf · python-docx

## Run it
```bash
pip install flask flask-sqlalchemy scikit-learn joblib numpy pypdf python-docx
python app.py
# open http://127.0.0.1:5000/portals
```
Set `SECRET_KEY` and the admin credentials as environment variables before any real use.

## Datasets
Dataset 1: [Real / Fake Job Posting Prediction (Kaggle)](https://www.kaggle.com/datasets/shivamb/real-or-fake-fake-jobposting-prediction)


## Limitations
English text only · recall is about 63% · no employer verification · some datasets may be synthetic.

## Author
Tamannah
