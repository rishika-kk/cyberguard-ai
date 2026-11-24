import re
import streamlit as st
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# --- 1. Lightweight Built-in ML Model (Trains in <0.1 sec) ---
TRAINING_DATA = [
    ("Urgent! Your SBI bank account will be blocked today. Click http://bit.ly/kyc-update to verify OTP.", 1),
    ("Congratulations! You won Rs 50,000 cashback. Claim now by entering your UPI PIN.", 1),
    ("Electricity bill unpaid. Power will be disconnected tonight at 9 PM. Call 9876543210 immediately.", 1),
    ("Dear customer, update your PAN card details within 24 hours to avoid account suspension.", 1),
    ("Work from home and earn Rs 5000 daily! Click link to join WhatsApp group.", 1),
    ("Your parcel delivery failed due to incomplete address. Pay Rs 15 at http://track-pkg.top", 1),
    ("Hi, are we still meeting at the library at 4 PM for project discussion?", 0),
    ("Your Amazon order #402-192837 has been shipped and will arrive tomorrow.", 0),
    ("Reminder: Internal viva exam is scheduled for this week. Please bring your project file.", 0),
    ("Can you please share the notes from today's cybersecurity lecture?", 0),
    ("Your OTP for login is 482910. Do not share it with anyone. Valid for 10 minutes.", 0),
    ("Thank you for attending the workshop. Your certificate has been sent to your email.", 0),
]

texts = [item[0] for item in TRAINING_DATA]
labels = [item[1] for item in TRAINING_DATA]

vectorizer = TfidfVectorizer(stop_words="english")
X_train = vectorizer.fit_transform(texts)
model = MultinomialNB()
model.fit(X_train, labels)

# --- 2. Heuristic & URL Forensics Analyzer ---
URGENCY_WORDS = ["urgent", "immediately", "24 hours", "blocked", "suspended", "disconnected", "today", "tonight", "expire"]
SENSITIVE_WORDS = ["otp", "pin", "upi", "password", "kyc", "cvv", "bank account", "pan card", "verify"]
BAIT_WORDS = ["congratulations", "won", "lottery", "cashback", "prize", "free", "earn daily", "claim now"]
SUSPICIOUS_DOMAINS = ["bit.ly", "tinyurl", ".top", ".xyz", ".click", ".info", "http://"]

def analyze_message(msg: str):
    msg_lower = msg.lower()
    red_flags = []
    rule_score = 0

    # Check Urgency
    found_urgency = [w for w in URGENCY_WORDS if w in msg_lower]
    if found_urgency:
        rule_score += 25
        red_flags.append(f"High Urgency / Fear Tactics detected: `{', '.join(found_urgency)}`")

    # Check Sensitive Data Request
    found_sensitive = [w for w in SENSITIVE_WORDS if w in msg_lower]
    if found_sensitive:
        rule_score += 30
        red_flags.append(f"Sensitive Credential / KYC Trigger: `{', '.join(found_sensitive)}`")

    # Check Reward Bait
    found_bait = [w for w in BAIT_WORDS if w in msg_lower]
    if found_bait:
        rule_score += 25
        red_flags.append(f"Unrealistic Reward / Lottery Bait: `{', '.join(found_bait)}`")

    # Check Suspicious URLs
    urls = re.findall(r"(https?://\S+|www\.\S+)", msg_lower)
    if urls:
        for u in urls:
            if any(sd in u for sd in SUSPICIOUS_DOMAINS):
                rule_score += 35
                red_flags.append(f"Suspicious / Unencrypted URL detected: `{u}`")
            else:
                rule_score += 10
                red_flags.append(f"External Link present (verify domain carefully): `{u}`")

    # ML Probability Score
    vec = vectorizer.transform([msg])
    ml_prob = model.predict_proba(vec)[0][1] * 100

    # Hybrid Final Risk Score
    final_risk = min(round((0.55 * min(rule_score, 100)) + (0.45 * ml_prob), 1), 100.0)
    return final_risk, round(ml_prob, 1), red_flags

# --- 3. Streamlit UI ---
st.set_page_config(page_title="CyberGuard AI - Scam Shield", page_icon="🛡️", layout="centered")

st.title("🛡️ CyberGuard AI: Phishing & Scam Shield")
st.caption("Real-time Social Engineering, URL Forensics & ML Threat Detector")

sample_choice = st.selectbox(
    "Quick Test Samples (for Live Viva Demo):",
    [
        "Custom Message",
        "🚨 Scam Sample: Urgent! Your bank KYC is pending. Account will be blocked today. Click http://bit.ly/verify-kyc and share OTP.",
        "🎁 Lottery Scam: Congratulations! You won Rs 25,000 cashback. Claim now by entering your UPI PIN.",
        "✅ Safe Sample: Hi Rishika, please bring your Product Toolkit file and Minor Project GitHub link tomorrow.",
    ]
)

default_text = "" if sample_choice == "Custom Message" else sample_choice.split(": ", 1)[1]
user_msg = st.text_area("Paste suspicious SMS, WhatsApp forward, or Email here:", value=default_text, height=140)

if st.button("Scan Message for Threats", type="primary"):
    if not user_msg.strip():
        st.warning("Please enter a message to scan.")
    else:
        risk_score, ml_score, flags = analyze_message(user_msg)

        st.divider()
        c1, c2 = st.columns(2)
        c1.metric("Overall Threat Risk Score", f"{risk_score}%")
        c2.metric("ML Scam Probability", f"{ml_score}%")
        st.progress(int(risk_score))

        if risk_score >= 60:
            st.error("🚨 **HIGH RISK: Likely Phishing / Scam Attempt!** Do NOT click any links or share OTP/PIN.")
        elif risk_score >= 30:
            st.warning("⚠️ **MEDIUM RISK: Suspicious Indicators Found.** Verify sender through official channels.")
        else:
            st.success("✅ **LOW RISK: Looks Safe.** No major phishing or social-engineering red flags detected.")

        if flags:
            st.subheader("🔍 Detected Threat Indicators")
            for f in flags:
                st.write(f"- {f}")