from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

# Configure headless Chrome
options = Options()
options.add_argument("--headless")
options.add_argument("--disable-gpu")
driver = webdriver.Chrome(options=options)

BASE_URL = "https://www.zoom.com/en/trust/security-bulletin/"
PAGE_LIMIT = 2  # Adjust as needed
all_data = []

for page in range(1, PAGE_LIMIT + 1):
    url = f"{BASE_URL}?pageSize=20&page={page}&sort=newestupdated"
    print(f"\n--- Scraping Page {page} ---")
    driver.get(url)

    try:
        # Wait until bulletin items are present
        WebDriverWait(driver, 10).until(
            EC.presence_of_all_elements_located((By.CLASS_NAME, "c-card-list__item"))
        )
        bulletins = driver.find_elements(By.CLASS_NAME, "c-card-list__item")
    except:
        print("No bulletins found on this page.")
        continue

    for bulletin in bulletins:
        try:
            title = bulletin.find_element(By.CLASS_NAME, "c-card__title").text.strip()
        except:
            title = "N/A"

        cve = severity = date = "N/A"
        meta_items = bulletin.find_elements(By.CLASS_NAME, "c-card__meta-item")
        for item in meta_items:
            text = item.text.strip()
            if 'CVE' in text:
                cve = text
            elif any(sev in text for sev in ['Low', 'Medium', 'High', 'Critical']):
                severity = text
            elif 'Published' in text:
                date = text.replace("Published ", "")

        print(f"Title          : {title}")
        print(f"CVE            : {cve}")
        print(f"Severity       : {severity}")
        print(f"Date Published : {date}")
        print("-" * 50)

        all_data.append({
            'Title': title,
            'CVE': cve,
            'Severity': severity,
            'Date Published': date
        })

    time.sleep(2)  # Be polite to the server

driver.quit()

print(f"\n✅ Total vulnerabilities extracted: {len(all_data)}")
