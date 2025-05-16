import requests
from bs4 import BeautifulSoup
import re
from html import unescape

cisco = "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"
ubuntu = "https://ubuntu.com/security/notices/rss.xml"
fortinet = "https://filestore.fortinet.com/fortiguard/rss/iotapp.xml"

response = requests.get(cisco)
soup = BeautifulSoup(response.content, 'xml')

for item in soup.find_all('item'):
    title = item.title.text
    pub_date = item.pubDate.text
    link = item.link.text
    desc_raw = item.description.text
    desc_unescaped = unescape(desc_raw)
    desc_clean = BeautifulSoup(desc_unescaped, "html.parser").get_text()
    match = re.search(r"Security Impact Rating:\s*(\w+)", desc_clean)
    rating = match.group(1) if match else "Not found"

    print(f"Title: {title}")
    print(f"Published: {pub_date}")
    print(f"Link: {link}")
    print(f"Description: {desc_clean[:100]}...")
    print(f"Severity: {rating}")
    print("-" * 100)
