#!/usr/bin/env python3
"""
Black Hat Arsenal Web Scraper
examples:
python3 crawl_arsenal.py --region us --year 25
python3 crawl_arsenal.py --region eu --year 24
"""

import argparse
import time
import logging
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def setup_driver(headless=True):
    """Set up Chrome WebDriver with optimized options"""
    chrome_options = Options()
    if headless:
        chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
    
    return webdriver.Chrome(options=chrome_options)

def wait_for_page_load(driver, timeout=15):
    """Wait for page to fully load"""
    try:
        WebDriverWait(driver, timeout).until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )
        time.sleep(2)  # Additional wait for dynamic content
        return True
    except TimeoutException:
        logger.warning("Page load timeout, continuing anyway...")
        return False

def find_arsenal_links(driver, base_url):
    """Find arsenal links with multiple selector strategies"""
    selectors_to_try = [
        'a[itemprop="summary"]',
        'a[href*="#arsenal"]',
        '.arsenal-item a',
        '.schedule-item a',
        'a[href*="arsenal"]',
        '.event-item a'
    ]
    
    links = []
    for selector in selectors_to_try:
        try:
            elements = driver.find_elements(By.CSS_SELECTOR, selector)
            if elements:
                logger.info(f"Found {len(elements)} links using selector: {selector}")
                links = elements
                break
        except Exception as e:
            logger.debug(f"Selector {selector} failed: {e}")
    
    if not links:
        # Try to find any links as fallback
        try:
            all_links = driver.find_elements(By.TAG_NAME, "a")
            links = [link for link in all_links if link.get_attribute("href") and "#" in link.get_attribute("href")]
            logger.info(f"Fallback: Found {len(links)} anchor links")
        except Exception as e:
            logger.error(f"All link finding strategies failed: {e}")
    
    return links

def extract_content_from_page(driver, url, timeout=15):
    """Extract content from a specific page with multiple strategies"""
    try:
        driver.get(url)
        wait_for_page_load(driver, timeout)
        
        # Try different selectors for summary and description
        summary_selectors = [
            'h2[itemprop="summary"]',
            'h1[itemprop="summary"]',
            '.summary h2',
            '.title h2',
            'h2.title',
            'h1.title'
        ]
        
        description_selectors = [
            'div[itemprop="description"]',
            '.description',
            '.content',
            '.detail-content',
            '.event-description'
        ]
        
        summary = None
        description = None
        
        # Find summary
        for selector in summary_selectors:
            try:
                element = driver.find_element(By.CSS_SELECTOR, selector)
                summary = element.text.strip()
                if summary:
                    break
            except NoSuchElementException:
                continue
        
        # Find description
        for selector in description_selectors:
            try:
                element = driver.find_element(By.CSS_SELECTOR, selector)
                description = element.get_attribute('innerHTML').replace('<br>', '\n').strip()
                if description:
                    break
            except NoSuchElementException:
                continue
        
        if not summary:
            # Try to get page title as fallback
            try:
                summary = driver.find_element(By.TAG_NAME, "title").get_attribute("text")
            except:
                summary = "No title found"
        
        if not description:
            # Try to get any text content as fallback
            try:
                body = driver.find_element(By.TAG_NAME, "body")
                description = body.text[:500] + "..." if len(body.text) > 500 else body.text
            except:
                description = "No description found"
        
        return summary, description
        
    except Exception as e:
        logger.error(f"Error extracting content from {url}: {e}")
        return None, None

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Crawl Black Hat Arsenal page and extract content.")
    parser.add_argument('--region', type=str, default='asia', choices=['asia', 'us', 'eu'],
                        help='Region to target (asia, us, eu)')
    parser.add_argument('--year', type=str, default='24', help='Year of the event (e.g., 24 for 2024)')
    parser.add_argument('--headless', action='store_true', default=True, help='Run in headless mode')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode (non-headless)')
    parser.add_argument('--output', type=str, default='extracted_content.txt', help='Output file name')
    
    args = parser.parse_args()
    
    # Debug: Print the arguments
    logger.info(f"Arguments - Region: {args.region}, Year: {args.year}")
    
    if args.debug:
        args.headless = False
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize the WebDriver
    driver = setup_driver(headless=args.headless)
    
    try:
        # Construct the base URL
        base_url = f"https://www.blackhat.com/{args.region}-{args.year}/arsenal/schedule/"
        logger.info(f"Visiting: {base_url}")
        
        # Open the website
        driver.get(base_url)
        
        # Check if page loaded successfully
        if "404" in driver.title or "not found" in driver.title.lower():
            logger.error(f"Page not found: {base_url}")
            logger.info("Possible reasons: Invalid region/year combination or page structure changed")
            return
        
        logger.info(f"Page title: {driver.title}")
        
        # Wait for page to load
        wait_for_page_load(driver)
        
        # Debug: Save page source if in debug mode
        if args.debug:
            with open('page_source_debug.html', 'w', encoding='utf-8') as f:
                f.write(driver.page_source)
            logger.debug("Page source saved to page_source_debug.html")
        
        # Find arsenal links
        links = find_arsenal_links(driver, base_url)
        
        if not links:
            logger.error("No links found. The page structure might have changed.")
            logger.info("Check the page manually or use --debug flag to inspect the HTML")
            return
        
        logger.info(f"Found {len(links)} links to process")
        
        # Open output file
        with open(args.output, 'w', encoding='utf-8') as file:
            processed = 0
            for i, link in enumerate(links):
                href = link.get_attribute("href")
                if not href:
                    continue
                
                # Construct full URL
                if href.startswith("#"):
                    full_url = f"{base_url}{href}"
                elif not href.startswith("http"):
                    full_url = f"https://www.blackhat.com{href}"
                else:
                    full_url = href
                
                logger.info(f"Processing link {i+1}/{len(links)}: {full_url}")
                
                # Extract content
                summary, description = extract_content_from_page(driver, full_url)
                
                if summary and description:
                    file.write(f"<details>\n")
                    file.write(f"  <summary>{summary}</summary>\n")
                    file.write(f"  {description}\n")
                    file.write(f"</details>\n\n")
                    processed += 1
                    logger.info(f"Successfully extracted content for: {summary[:50]}...")
                else:
                    logger.warning(f"Failed to extract content from: {full_url}")
                
                # Small delay to be respectful
                time.sleep(1)
        
        logger.info(f"Scraping completed. Processed {processed}/{len(links)} links.")
        logger.info(f"Data written to {args.output}")
        
    except KeyboardInterrupt:
        logger.info("Scraping interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        driver.quit()

if __name__ == "__main__":
    main()