import requests
from bs4 import BeautifulSoup
import re
import json
from html import unescape
import random
from pymongo import mongo_client

# Setting DataBase
client = mongo_client.MongoClient("mongodb://localhost:27017/")
db = client["VulnarabilityData"]
collection = db["VulnarabilityData"]
microsoft_coll = db["Microsoft"]
cisco_coll = db["Cisco"]
ubuntu_coll = db["Ubuntu"]
fortinet_coll = db["Fortinet"]

# Souces Links
cisco = "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"
ubuntu = "https://ubuntu.com/security/notices/rss.xml"
fortinet = "https://filestore.fortinet.com/fortiguard/rss/iotapp.xml"
microsoft = "https://api.msrc.microsoft.com/update-guide/rss"

source_link = [cisco, ubuntu, fortinet, microsoft]

for i in source_link:
    response = requests.get(i)
    soup = BeautifulSoup(response.content, 'xml')
    severity = ["Low", "High", "Critical"]
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
        if "ubuntu" in link:
            vendor = "Ubuntu"
            collection = ubuntu_coll
        if "microsoft" in link:
            vendor = "Microsoft"
            collection = microsoft_coll
        if "fortinet" in link:
            vendor = "Fortinet"
            collection = fortinet_coll

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
    print(f"Data saved in database for {i}")