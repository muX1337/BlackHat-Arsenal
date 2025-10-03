#!/usr/bin/env python3
"""
Black Hat Arsenal Web Scraper (Playwright-first with Selenium fallback)

Examples:
  python3 crawl-arsenal.py --region us --year 25
  python3 crawl-arsenal.py --region eu --year 24
  
# Force a specific engine if you want:
python3 crawl-arsenal.py --region eu --year 24 --engine playwright
python3 crawl-arsenal.py --region eu --year 24 --engine selenium

Notes:
- Primary engine: Playwright (sync API)
- Fallback: Selenium (only used if Playwright import/launch/navigation fails)
"""

import argparse
import time
import logging
import sys
from typing import List, Tuple, Optional

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ---------- Shared selectors ----------
SUMMARY_SELECTORS = [
    'h2[itemprop="summary"]',
    'h1[itemprop="summary"]',
    '.summary h2',
    '.title h2',
    'h2.title',
    'h1.title',
]

DESCRIPTION_SELECTORS = [
    'div[itemprop="description"]',
    '.description',
    '.content',
    '.detail-content',
    '.event-description',
]

LINK_SELECTORS = [
    'a[itemprop="summary"]',
    'a[href*="#arsenal"]',
    '.arsenal-item a',
    '.schedule-item a',
    'a[href*="arsenal"]',
    '.event-item a',
]


def build_base_url(region: str, year: str) -> str:
    return f"https://www.blackhat.com/{region}-{year}/arsenal/schedule/"


# =====================================================
#                PLAYWRIGHT IMPLEMENTATION
# =====================================================
def run_with_playwright(region: str, year: str, headless: bool, debug: bool, output_file: str) -> None:
    """
    Scrape using Playwright (sync API). Raises Exception on failure so the caller can fallback.
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError  # type: ignore
    except Exception as e:
        raise RuntimeError(f"Playwright import failed: {e}")

    base_url = build_base_url(region, year)
    logger.info(f"[Playwright] Visiting: {base_url} (headless={headless})")

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=headless, args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ])
            context = browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/119.0.0.0 Safari/537.36"),
            )
            page = context.new_page()
        except Exception as e:
            raise RuntimeError(f"Playwright launch/new_context failed: {e}")

        try:
            page.goto(base_url, wait_until="load", timeout=30000)
            # Wait for additional network to settle; ignore timeout
            try:
                page.wait_for_load_state("networkidle", timeout=15000)
            except PlaywrightTimeoutError:
                logger.warning("[Playwright] networkidle wait timed out; continuing.")
        except Exception as e:
            raise RuntimeError(f"Playwright navigation to {base_url} failed: {e}")

        title = page.title() or ""
        if "404" in title or "not found" in title.lower():
            raise RuntimeError(f"[Playwright] Page not found: {base_url}")

        if debug:
            with open('page_source_debug.html', 'w', encoding='utf-8') as f:
                f.write(page.content())

        # -------- Find links --------
        link_hrefs: List[str] = []
        for sel in LINK_SELECTORS:
            try:
                elements = page.query_selector_all(sel)
                if elements:
                    link_hrefs = []
                    for el in elements:
                        href = el.get_attribute("href")
                        if href:
                            link_hrefs.append(href)
                    if link_hrefs:
                        logger.info(f"[Playwright] Found {len(link_hrefs)} links using selector: {sel}")
                        break
            except Exception as e:
                logger.debug(f"[Playwright] Selector {sel} failed: {e}")

        # Generic fallback: collect any anchors with '#' href
        if not link_hrefs:
            try:
                all_links = page.query_selector_all("a")
                link_hrefs = []
                for el in all_links:
                    href = el.get_attribute("href")
                    if href and "#" in href:
                        link_hrefs.append(href)
                if link_hrefs:
                    logger.info(f"[Playwright] Fallback: Found {len(link_hrefs)} anchor links")
            except Exception as e:
                raise RuntimeError(f"[Playwright] Failed to collect links: {e}")

        if not link_hrefs:
            raise RuntimeError("[Playwright] No links found. The page structure might have changed.")

        # -------- Process each link and write results --------
        processed = 0
        with open(output_file, 'w', encoding='utf-8') as outf:
            for idx, href in enumerate(link_hrefs, 1):
                # Normalize URL
                if href.startswith("#"):
                    full_url = f"{base_url}{href}"
                elif not href.startswith("http"):
                    full_url = f"https://www.blackhat.com{href}"
                else:
                    full_url = href

                logger.info(f"[Playwright] Processing link {idx}/{len(link_hrefs)}: {full_url}")
                summary, description = extract_with_playwright(page, full_url)

                if summary and description:
                    outf.write("<details>\n")
                    outf.write(f"  <summary>{summary}</summary>\n")
                    outf.write(f"  {description}\n")
                    outf.write("</details>\n\n")
                    processed += 1
                    logger.info(f"[Playwright] Extracted: {summary[:60]}...")
                else:
                    logger.warning(f"[Playwright] Failed to extract content from: {full_url}")

                time.sleep(1)  # be polite

        logger.info(f"[Playwright] Scraping completed. Processed {processed}/{len(link_hrefs)} links.")
        logger.info(f"[Playwright] Data written to {output_file}")


def first_nonempty_text(page, selectors: List[str]) -> Optional[str]:
    for sel in selectors:
        try:
            el = page.query_selector(sel)
            if el:
                # Try text_content first
                text = el.text_content() or ""
                text = text.strip()
                if text:
                    return text
        except Exception:
            pass
    return None


def first_nonempty_html(page, selectors: List[str]) -> Optional[str]:
    for sel in selectors:
        try:
            el = page.query_selector(sel)
            if el:
                html = el.inner_html() or ""
                html = html.replace("<br>", "\n").strip()
                if html:
                    return html
        except Exception:
            pass
    return None


def extract_with_playwright(page, url: str, timeout_ms: int = 30000) -> Tuple[Optional[str], Optional[str]]:
    try:
        page.goto(url, wait_until="load", timeout=timeout_ms)
        try:
            page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass

        summary = first_nonempty_text(page, SUMMARY_SELECTORS)
        description = first_nonempty_html(page, DESCRIPTION_SELECTORS)

        if not summary:
            try:
                summary = page.title() or "No title found"
            except Exception:
                summary = "No title found"

        if not description:
            try:
                body_text = page.text_content("body") or ""
                if len(body_text) > 500:
                    description = body_text[:500] + "..."
                else:
                    description = body_text or "No description found"
            except Exception:
                description = "No description found"

        return summary, description
    except Exception as e:
        logger.error(f"[Playwright] Error extracting from {url}: {e}")
        return None, None


# =====================================================
#                SELENIUM FALLBACK
# =====================================================
def run_with_selenium(region: str, year: str, headless: bool, debug: bool, output_file: str) -> None:
    """Selenium fallback: mirrors the user's original approach as closely as possible."""
    try:
        from selenium import webdriver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.common.exceptions import TimeoutException, NoSuchElementException
    except Exception as e:
        raise RuntimeError(f"Selenium import failed: {e}")

    def setup_driver(headless_opt=True):
        chrome_options = Options()
        if headless_opt:
            chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                                    "Chrome/119.0.0.0 Safari/537.36")
        return webdriver.Chrome(options=chrome_options)

    def wait_for_page_load(driver, timeout=15):
        try:
            WebDriverWait(driver, timeout).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
            time.sleep(2)
            return True
        except TimeoutException:
            logger.warning("[Selenium] Page load timeout, continuing anyway...")
            return False

    def find_arsenal_links(driver) -> List[str]:
        links = []
        for sel in LINK_SELECTORS:
            try:
                elements = driver.find_elements(By.CSS_SELECTOR, sel)
                if elements:
                    links = [e.get_attribute("href") for e in elements if e.get_attribute("href")]
                    if links:
                        logger.info(f"[Selenium] Found {len(links)} links using selector: {sel}")
                        break
            except Exception as e:
                logger.debug(f"[Selenium] Selector {sel} failed: {e}")

        if not links:
            try:
                all_links = driver.find_elements(By.TAG_NAME, "a")
                links = [a.get_attribute("href") for a in all_links if a.get_attribute("href") and "#" in a.get_attribute("href")]
                if links:
                    logger.info(f"[Selenium] Fallback: Found {len(links)} anchor links")
            except Exception as e:
                logger.error(f"[Selenium] Failed collecting links: {e}")
                return []

        return links

    def extract_content_from_page(driver, url, timeout=15) -> Tuple[Optional[str], Optional[str]]:
        try:
            driver.get(url)
            wait_for_page_load(driver, timeout)

            summary = None
            description = None

            # Summary
            for sel in SUMMARY_SELECTORS:
                try:
                    el = driver.find_element(By.CSS_SELECTOR, sel)
                    txt = el.text.strip()
                    if txt:
                        summary = txt
                        break
                except NoSuchElementException:
                    continue

            # Description
            for sel in DESCRIPTION_SELECTORS:
                try:
                    el = driver.find_element(By.CSS_SELECTOR, sel)
                    html = el.get_attribute("innerHTML").replace("<br>", "\n").strip()
                    if html:
                        description = html
                        break
                except NoSuchElementException:
                    continue

            if not summary:
                try:
                    summary = driver.find_element(By.TAG_NAME, "title").get_attribute("text") or "No title found"
                except Exception:
                    summary = "No title found"

            if not description:
                try:
                    body = driver.find_element(By.TAG_NAME, "body")
                    txt = body.text or ""
                    description = (txt[:500] + "...") if len(txt) > 500 else (txt or "No description found")
                except Exception:
                    description = "No description found"

            return summary, description
        except Exception as e:
            logger.error(f"[Selenium] Error extracting content from {url}: {e}")
            return None, None

    base_url = build_base_url(region, year)
    logger.info(f"[Selenium] Visiting: {base_url} (headless={headless})")

    driver = setup_driver(headless_opt=headless)
    try:
        driver.get(base_url)
        wait_for_page_load(driver)

        title = driver.title or ""
        if "404" in title or "not found" in title.lower():
            raise RuntimeError(f"[Selenium] Page not found: {base_url}")

        if debug:
            with open('page_source_debug.html', 'w', encoding='utf-8') as f:
                f.write(driver.page_source)
            logger.debug("[Selenium] Page source saved to page_source_debug.html")

        link_hrefs = find_arsenal_links(driver)
        if not link_hrefs:
            raise RuntimeError("[Selenium] No links found. The page structure might have changed.")

        processed = 0
        with open(output_file, 'w', encoding='utf-8') as outf:
            for i, href in enumerate(link_hrefs, 1):
                if href.startswith("#"):
                    full_url = f"{base_url}{href}"
                elif not href.startswith("http"):
                    full_url = f"https://www.blackhat.com{href}"
                else:
                    full_url = href

                logger.info(f"[Selenium] Processing link {i}/{len(link_hrefs)}: {full_url}")
                summary, description = extract_content_from_page(driver, full_url)

                if summary and description:
                    outf.write("<details>\n")
                    outf.write(f"  <summary>{summary}</summary>\n")
                    outf.write(f"  {description}\n")
                    outf.write("</details>\n\n")
                    processed += 1
                    logger.info(f"[Selenium] Extracted: {summary[:60]}...")
                else:
                    logger.warning(f"[Selenium] Failed to extract content from: {full_url}")

                time.sleep(1)

        logger.info(f"[Selenium] Scraping completed. Processed {processed}/{len(link_hrefs)} links.")
        logger.info(f"[Selenium] Data written to {output_file}")
    finally:
        try:
            driver.quit()
        except Exception:
            pass


# =====================================================
#                      CLI
# =====================================================
def main():
    parser = argparse.ArgumentParser(description="Crawl Black Hat Arsenal page and extract content (Playwright-first with Selenium fallback).")
    parser.add_argument('--region', type=str, default='asia', choices=['asia', 'us', 'eu'], help='Region to target (asia, us, eu)')
    parser.add_argument('--year', type=str, default='24', help='Year of the event (e.g., 24 for 2024)')
    parser.add_argument('--headless', action='store_true', default=True, help='Run in headless mode')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode (non-headless + save HTML)')
    parser.add_argument('--output', type=str, default='extracted_content.txt', help='Output file name')
    parser.add_argument('--engine', type=str, default='auto', choices=['auto', 'playwright', 'selenium'], help='Force engine or use auto with fallback')

    args = parser.parse_args()

    # If debug is set, disable headless and bump logging
    if args.debug:
        args.headless = False
        logging.getLogger().setLevel(logging.DEBUG)

    # Try Playwright first unless forced otherwise
    if args.engine in ('auto', 'playwright'):
        try:
            run_with_playwright(args.region, args.year, args.headless, args.debug, args.output)
            return
        except Exception as e:
            logger.error(f"[Playwright] Failed: {e}")
            if args.engine == 'playwright':
                logger.error("Playwright was forced but failed. Exiting.")
                sys.exit(2)
            logger.info("Falling back to Selenium...")

    # Fallback to Selenium
    try:
        run_with_selenium(args.region, args.year, args.headless, args.debug, args.output)
    except Exception as e:
        logger.error(f"[Selenium] Failed: {e}")
        logger.error("Both Playwright and Selenium failed.")
        sys.exit(3)


if __name__ == "__main__":
    main()
