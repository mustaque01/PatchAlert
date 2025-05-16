import requests
from bs4 import BeautifulSoup

url = 'https://msrc.microsoft.com/update-guide/vulnerability'
headers = {'User-Agent': 'Mozilla/5.0'}

response = requests.get(url, headers=headers)
soup = BeautifulSoup(response.text, 'html.parser')

vuln_entries = soup.find_all()
for entry in vuln_entries:
    print(entry.text)
