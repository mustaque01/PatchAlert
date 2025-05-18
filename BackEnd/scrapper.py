import requests
from bs4 import BeautifulSoup
import re
import json
from html import unescape
from pymongo import mongo_client

client = mongo_client.MongoClient("mongodb://localhost:27017/")
db = client["VulnarabilityData"]
collection = db["VulnarabilityData"]

cisco = "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"
ubuntu = "https://ubuntu.com/security/notices/rss.xml"
fortinet = "https://filestore.fortinet.com/fortiguard/rss/iotapp.xml"
microsoft = "https://api.msrc.microsoft.com/update-guide/rss"

response = requests.get(ubuntu)
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
    rating = match.group(1) if match else "Not found"
    
    if "cisco" in link:
        vendor = "Cisco"
    if "ubuntu" in link:
        vendor = "Ubuntu"
    if "microsoft" in link:
        vendor = "Microsoft"
    if "fortinet" in link:
        vendor = "Fortinet"

    collection.update_one(
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

print("Data saved to MongoDB collection 'vulnerabilities' in 'vulnerability_db' database.")
