import requests
from bs4 import BeautifulSoup
import re
import random
import smtplib
from pymongo import MongoClient
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from html import unescape

# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")
db = client["VulnarabilityData"]
microsoft_coll = db["Microsoft"]
cisco_coll = db["Cisco"]
ubuntu_coll = db["Ubuntu"]
fortinet_coll = db["Fortinet"]
emails_coll = db["Technician Email"]

# Email Configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "umarroxx777@gmail.com"
SENDER_PASSWORD = "tttk jjjy gfqa rodn"  # Use App Password

# RSS Feed Sources
source_link = [
    "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
    "https://ubuntu.com/security/notices/rss.xml",
    "https://filestore.fortinet.com/fortiguard/rss/iotapp.xml",
    "https://api.msrc.microsoft.com/update-guide/rss"
]

severity_levels = ["Low", "High", "Critical"]

# Email sending function
def send_email_custom(sender_email, sender_password, receiver_email, subject, body, smtp_server="smtp.gmail.com", smtp_port=587):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
            print(f"✅ Email sent to {receiver_email}")
    except Exception as e:
        print(f"❌ Failed to send email to {receiver_email}: {e}")

# Main Scraper and Notifier
for url in source_link:
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'xml')

    for item in soup.find_all('item'):
        title = item.title.text
        pub_date = item.pubDate.text
        link = item.link.text
        desc_raw = item.description.text
        desc_unescaped = unescape(desc_raw)
        desc_clean = BeautifulSoup(desc_unescaped, "html.parser").get_text()

        match = re.search(r"Security Impact Rating:\s*(\w+)", desc_clean)
        rating = match.group(1) if match else random.choice(severity_levels)

        if "cisco" in link:
            vendor = "Cisco"
            collection = cisco_coll
        elif "ubuntu" in link:
            vendor = "Ubuntu"
            collection = ubuntu_coll
        elif "microsoft" in link:
            vendor = "Microsoft"
            collection = microsoft_coll
        elif "fortinet" in link:
            vendor = "Fortinet"
            collection = fortinet_coll
        else:
            continue

        result = collection.update_one(
            {"link": link},
            {"$set": {
                "vendor": vendor,
                "title": title,
                "published": pub_date,
                "link": link,
                "description": desc_clean,
                "severity": rating
            }},
            upsert=True
        )

        # Send email if new entry is added
        if result.upserted_id:
            subject = f"[{vendor} Alert] {title}"
            body = f"""
            New vulnerability alert from {vendor}!

            Title: {title}
            Severity: {rating}
            Published: {pub_date}
            Link: {link}

            Description:
            {desc_clean}
            """
            matching_techs = emails_coll.find({"category": rating})
            for tech in matching_techs:
                send_email_custom(SENDER_EMAIL, SENDER_PASSWORD, tech['email'], subject, body)

    print(f"✔ Data processed for {url}")
