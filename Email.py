
import re

print("=" * 50)
print("             EMAIL RISK ANALYZER")
print("=" * 50)

# Get email content
email = input("\nPaste the email content:\n\n").lower()

risk_score = 0
warnings = []

# 1. Check urgent language
urgent_words = [
    "urgent", "immediately", "act now",
    "within 24 hours", "limited time",
    "final warning", "expires today"
]

urgent_found = [word for word in urgent_words if word in email]

if urgent_found:
    risk_score += 2
    warnings.append("Urgent or pressure-based language detected.")

# 2. Check suspicious links
urls = re.findall(r'https?://[^\s<>"\']+', email)

suspicious_links = []

for url in urls:
    if url.startswith("http://"):
        suspicious_links.append(url)
    elif any(short in url.lower() for short in [
        "bit.ly", "tinyurl.com", "t.co", "shorturl.at"
    ]):
        suspicious_links.append(url)

if suspicious_links:
    risk_score += 3
    warnings.append("Potentially suspicious or shortened links detected.")

elif urls:
    risk_score += 1
    warnings.append("Links found. Verify their destinations before clicking.")

# 3. Check sensitive information requests
sensitive_words = [
    "password", "otp", "pin",
    "cvv", "social security number",
    "login credentials", "bank details"
]

sensitive_found = [
    word for word in sensitive_words if word in email
]

if sensitive_found:
    risk_score += 3
    warnings.append("Sensitive personal or financial information requested.")

# 4. Check financial requests
financial_words = [
    "transfer money", "send money",
    "bank account", "credit card",
    "payment required", "wire transfer"
]

financial_found = [
    word for word in financial_words if word in email
]

if financial_found:
    risk_score += 2
    warnings.append("Financial request detected.")

# 5. Check threatening language
threat_words = [
    "account blocked", "account suspended",
    "account will be closed", "legal action",
    "account terminated"
]

threat_found = [
    word for word in threat_words if word in email
]

if threat_found:
    risk_score += 2
    warnings.append("Threatening or intimidating language detected.")

# Display results
print("\n" + "=" * 50)
print("                 ANALYSIS RESULT")
print("=" * 50)

if risk_score >= 6:
    print("EMAIL RISK LEVEL: HIGH RISK")
elif risk_score >= 3:
    print("EMAIL RISK LEVEL: MEDIUM RISK")
else:
    print("EMAIL RISK LEVEL: LOW RISK")

print("Risk Score:", risk_score)

# Display warnings
print("\nSUSPICIOUS PATTERNS:")

if warnings:
    for warning in warnings:
        print("[WARNING]", warning)
else:
    print("[SAFE CHECK] No known suspicious patterns detected.")

# Security recommendations
print("\nSECURITY RECOMMENDATIONS:")

if warnings:
    print("- Do not click suspicious links.")
    print("- Never share passwords, OTPs, or PINs.")
    print("- Verify the sender through an official channel.")
    print("- Do not make payments based on unexpected emails.")
else:
    print("- Continue checking the sender and links.")
    print("- Never share sensitive information through email.")

print("\nNOTE: This is a basic rule-based analyzer.")
print("It cannot guarantee that an email is safe.")

print("=" * 50)
print("              ANALYSIS COMPLETED")
print("=" * 50)
