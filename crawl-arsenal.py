#Usage
# python3 crawl_arsenal.py --region asia --year 24
# python3 crawl_arsenal.py --region us --year 25

import argparse
from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
from pathlib import Path

# Set up argument parser
parser = argparse.ArgumentParser(description="Crawl Black Hat Arsenal page and extract content.")
parser.add_argument('--region', type=str, default='asia', choices=['asia', 'us', 'eu'],
                    help='Region to target (asia, us, eu)')
parser.add_argument('--year', type=str, default='24', help='Year of the event (e.g., 24 for 2024)')
args = parser.parse_args()

# Set up Chrome options
chrome_options = Options()
chrome_options.add_argument("--headless")  # Run in headless mode

# Initialize the WebDriver
driver = webdriver.Chrome(options=chrome_options)

# Define the base URL pattern with placeholders for region and year
base_url_pattern = "https://www.blackhat.com/{region}-{year}/arsenal/schedule/"

# Construct the base URL using command-line arguments
base_url = base_url_pattern.format(region=args.region, year=args.year)

# Open the website
driver.get(base_url)

# Wait for the page to load
WebDriverWait(driver, 10).until(
    EC.presence_of_element_located((By.CSS_SELECTOR, 'a[itemprop="summary"]'))
)

# Extract the links with Selenium
links = driver.find_elements(By.CSS_SELECTOR, 'a[itemprop="summary"]')
print(f"Found {len(links)} links.")

# Open a file to write the results
with open('extracted_content.txt', 'w') as file:
    for link in links:
        href = link.get_attribute("href")
        if href.startswith("#"):
            full_url = f"{base_url}{href}"  # No need to remove the extra slashes
        else:
            full_url = href  # In case href is a full URL

        print(f"Visiting link: {full_url}")

        # Visit the link
        driver.get(full_url)

        # Wait for the summary and description to be present
        try:
            summary_element = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, 'h2[itemprop="summary"]'))
            )
            description_element = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, 'div[itemprop="description"]'))
            )

            summary = summary_element.text
            description = description_element.get_attribute('innerHTML').replace('<br>', '\n')

            # Write to file in the specified format
            file.write(f"<details>\n")
            file.write(f"  <summary>{summary}</summary>\n")
            file.write(f"  {description}\n")
            file.write(f"</details>\n\n")

        except Exception as e:
            print(f"Error: {e}")

# Close the browser
driver.quit()

print("Scraping completed and data written to extracted_content.txt.")
