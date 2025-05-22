import requests
from bs4 import BeautifulSoup
import re
import json
from html import unescape
import random
import smtplib
from pymongo import mongo_client
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Setting DataBase
client = mongo_client.MongoClient("mongodb://localhost:27017/")
db = client["VulnarabilityData"]
collection = db["VulnarabilityData"]
microsoft_coll = db["Microsoft"]
cisco_coll = db["Cisco"]
ubuntu_coll = db["Ubuntu"]
fortinet_coll = db["Fortinet"]
emails_coll = db["Technician Email"]

# SMTP Email Config
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "umarroxx777@gmail.com"
SENDER_PASSWORD = "Um@r7860"

# Sources
source_link = [
    "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
    "https://ubuntu.com/security/notices/rss.xml",
    "https://filestore.fortinet.com/fortiguard/rss/iotapp.xml",
    "https://api.msrc.microsoft.com/update-guide/rss"
]

severity = ["Low", "High", "Critical"]

# Get technician emails
technicians = [e['email'] for e in emails_coll.find()]

# Helper: Send Email
def send_email(subject, body):
    for receiver in emails_coll:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = receiver
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SENDER_EMAIL, SENDER_PASSWORD)
                server.sendmail(SENDER_EMAIL, receiver, msg.as_string())
                print(f"Email sent to {receiver}")
        except Exception as e:
            print(f"Failed to send email to {receiver}: {e}")

# Main Scraper
for url in source_link:
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'xml')

    for item in soup.find_all('item'):
        vendor = ""
        title = item.title.text
        pub_date = item.pubDate.text
        link = item.link.text
        desc_raw = item.description.text
        desc_unescaped = unescape(desc_raw)
        desc_clean = BeautifulSoup(desc_unescaped, "html.parser").get_text()
        match = re.search(r"Security Impact Rating:\s*(\w+)", desc_clean)
        rating = match.group(1) if match else random.choice(severity)

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

        # Insert or Update
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

        # Send email only for new data
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
            send_email(subject, body)

    print(f"Data processed for {url}")
