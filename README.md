# 🛡️ CyberGuard AI — Real-Time Phishing & Scam Message Shield

A hybrid Machine Learning and Heuristic URL Forensics web application that detects phishing SMS, WhatsApp scams, and social-engineering messages in real time.

## 🚀 Why This Project?
Digital fraud via fake KYC alerts, urgent bank warnings, and shortened phishing links is a rapidly growing real-world threat. **CyberGuard AI** analyzes incoming messages using both a **Multinomial Naive Bayes ML classifier** and **rule-based social-engineering forensics** to explain *why* a message is risky.

## 🛠️ Tech Stack
- **Python 3.x**
- **Streamlit** (Interactive Web Dashboard)
- **Scikit-Learn** (`TfidfVectorizer` + `MultinomialNB` Classifier)
- **Regex URL Forensics Engine**

## 💻 How to Run
```bash
pip install -r requirements.txt
streamlit run app.py