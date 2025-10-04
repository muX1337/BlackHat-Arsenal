#!/usr/bin/env python3
"""
merge_arsenal_md_with_categories.py
-----------------------------------
Deterministic mapping: match <summary> title from your MD to the Black Hat
schedule title for the same year/region. Uses a rendered fetch:

1) Playwright (preferred)
2) Selenium (fallback)
3) requests (last resort)

MEA is skipped automatically (historical page differences / 404s).

Usage:
  python merge_arsenal_md_with_categories.py --root . --outdir Categories --unmatched-log unmatched.csv
  python merge_arsenal_md_with_categories.py --root . --outdir Categories --dry-run
"""
import argparse, os, re, sys, csv, time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

UA = "blackhat-arsenal-merger/3.0 (+github.com/muX1337/BlackHat-Arsenal)"
REGION_MAP = {"USA":"us","EU":"eu","ASIA":"asia","MEA":"mea"}
SKIP_REGIONS = {"MEA"}  # skip MEA as requested

@dataclass
class ToolItem:
    title: str
    description: str
    github: str
    year: str
    region: str

# -------------------- utils --------------------
def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def write_text(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def slugify_filename(value: str) -> str:
    v = value.strip().lower()
    v = re.sub(r"[^\w\s\-]+", "", v)
    v = re.sub(r"\s+", "-", v)
    v = re.sub(r"-{2,}", "-", v)
    v = v.strip("-")
    return v or "tool"

def norm_key(s: str) -> str:
    """Normalization for exact title key: lowercase, collapse spaces, normalize quotes."""
    s = s or ""
    s = s.strip().lower()
    s = s.replace("’", "'").replace("“","\"").replace("”","\"")
    s = re.sub(r"\s+", " ", s)
    return s

def norm_key_relaxed(s: str) -> str:
    """Relaxed normalization: drop most punctuation, keep alnum & spaces only."""
    s = s or ""
    s = s.lower()
    s = s.replace("’", "'").replace("“","\"").replace("”","\"")
    s = re.sub(r"[^a-z0-9]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def to_anchor_slug(s: str) -> str:
    """Approximate schedule anchor slug to use as a backup key."""
    s = s.lower()
    s = s.replace("’", "'")
    s = re.sub(r"[^a-z0-9\s\-]", "-", s)   # punctuation -> dashes
    s = re.sub(r"[\s_/]+", "-", s)         # spaces/slashes -> dash
    s = re.sub(r"-{2,}", "-", s)
    s = s.strip("-")
    return s

# -------------------- MD parsing --------------------
def parse_year_region_from_filename(filename: str) -> Optional[Tuple[str, str]]:
    base = os.path.basename(filename)
    m_year = re.search(r"(20(22|23|24|25))", base)
    m_region = re.search(r"\b(USA|EU|ASIA|MEA)\b", base, flags=re.I)
    if not m_year or not m_region:
        return None
    year = m_year.group(1)
    region = m_region.group(1).upper()
    return year, region

def find_md_files(root: str) -> List[str]:
    md_paths = []
    for dp, _, fns in os.walk(root):
        if any(d.lower() == "categories" for d in dp.split(os.sep)):
            continue
        for fn in fns:
            if not fn.lower().endswith(".md"):
                continue
            if "blackhat" not in fn.lower():
                continue
            full = os.path.join(dp, fn)
            if parse_year_region_from_filename(full):
                md_paths.append(full)
    return sorted(md_paths)

def extract_tools_from_md(md_path: str) -> List[Tuple[str, str]]:
    """
    Returns list of (title, details_html) for each <details> section.
    """
    text = read_text(md_path)
    soup = BeautifulSoup(text, "html.parser")
    tools = []
    for det in soup.find_all("details"):
        sum_el = det.find("summary")
        if not sum_el:
            continue
        title = sum_el.get_text(" ", strip=True)
        sum_el.extract()
        body_html = det.decode_contents()
        tools.append((title, body_html))
    return tools

def find_first_github_url(html_or_text: str) -> Optional[str]:
    text = BeautifulSoup(html_or_text, "html.parser").get_text(" ", strip=True)
    m = re.search(r"https?://github\.com/[^\s\)\]\}\>]+", text, flags=re.I)
    if m:
        return m.group(0).rstrip(").,;")
    return None

def clean_description_from_details(body_html: str) -> str:
    soup = BeautifulSoup(body_html, "html.parser")
    text = soup.get_text("\n", strip=False)
    lines = []
    for line in text.splitlines():
        lt = line.strip()
        if not lt:
            lines.append("")
            continue
        if re.search(r"github\.com", lt, flags=re.I):
            continue
        if re.search(r"^github\s*not\s*found\b", lt, flags=re.I):
            continue
        if re.match(r"^github\s*:?", lt, flags=re.I):
            continue
        lines.append(lt)
    cleaned = "\n".join(lines)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    return cleaned

# -------------------- Rendered fetch (Playwright -> Selenium -> Requests) --------------------
def fetch_with_playwright(url: str, wait_selector: str, timeout_ms: int = 45000) -> Optional[str]:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(user_agent=UA, java_script_enabled=True)
            page = context.new_page()
            page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            # wait for any of the content selectors to appear
            page.wait_for_selector(wait_selector, timeout=15000)
            html = page.content()
            context.close()
            browser.close()
            return html
    except Exception:
        return None

def fetch_with_selenium(url: str, wait_selector: str, timeout_s: int = 45) -> Optional[str]:
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service as ChromeService
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        from webdriver_manager.chrome import ChromeDriverManager
    except Exception:
        return None

    html = None
    options = Options()
    # chromium headless flags
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument(f"--user-agent={UA}")
    try:
        driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
        driver.set_page_load_timeout(timeout_s)
        driver.get(url)
        try:
            WebDriverWait(driver, min(timeout_s, 30)).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, wait_selector))
            )
        except Exception:
            pass  # even if wait times out, try to capture what we can
        html = driver.page_source
    except Exception:
        html = None
    finally:
        try:
            driver.quit()
        except Exception:
            pass
    return html

def fetch_with_requests(url: str, timeout_s: int = 30) -> Optional[str]:
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=timeout_s)
        r.raise_for_status()
        return r.text
    except Exception:
        return None

def fetch_schedule_rendered(url: str) -> Optional[str]:
    # Any of these indicates real session content
    wait_selector = ".data-container, .session-title, .list-view-filter-list-wrapper.session-track"
    html = fetch_with_playwright(url, wait_selector)
    if html:
        return html
    html = fetch_with_selenium(url, wait_selector)
    if html:
        return html
    return fetch_with_requests(url)

# -------------------- Schedule parsing --------------------
def normalize_category_label(raw: str) -> Optional[str]:
    if not raw:
        return None
    s = raw.strip()
    s = re.sub(r"\s+", " ", s)
    s_lower = s.lower()

    # Drop Arsenal Labs
    if re.search(r"\barsenal\s*labs?\b", s_lower):
        return None

    # Map icon-like tokens
    key = re.sub(r"[^a-z0-9/,&\s-]+", "", s_lower).strip()
    key = key.replace("_", " ").replace("-", " ")
    key = re.sub(r"\s+", " ", key)

    # Common intentional merges
    if "hardware" in key and "embedded" in key:
        return "Hardware/Embedded"
    if "ai" in key and "ml" in key and "data science" in key:
        return "AI, ML & Data Science"

    label = " ".join(w.capitalize() for w in key.split())
    return label or None

def icon_classes_to_categories(classes: List[str]) -> List[str]:
    cats = []
    for c in classes or []:
        base = re.sub(r"(_icon(list)?|-icon(list)?)$", "", c)
        if base == c:
            continue
        lab = normalize_category_label(base)
        if lab:
            cats.append(lab)
    return cats

def extract_categories_from_track_wrapper(wrapper) -> List[str]:
    categories: List[str] = []
    # text part
    strong = wrapper.find("strong") if wrapper else None
    text = wrapper.get_text(" ", strip=True) if wrapper else ""
    if strong and text:
        label = strong.get_text(strip=True)
        if text.lower().startswith(label.lower()):
            text = text[len(label):].lstrip(": ").strip()
    if text:
        if re.search(r"\bAI,\s*ML\s*&\s*Data\s*Science\b", text, flags=re.I):
            categories.append("AI, ML & Data Science")
        else:
            parts = [t.strip(" -•|") for t in re.split(r"[,/|•]+", text) if t.strip()]
            for p in parts:
                lab = normalize_category_label(p)
                if lab:
                    categories.append(lab)
    # icon class part
    classes = wrapper.get("class", []) if wrapper else []
    categories.extend(icon_classes_to_categories(classes))
    if wrapper:
        for icon in wrapper.select("[class]"):
            categories.extend(icon_classes_to_categories(icon.get("class", [])))
    # cleanup + dedupe
    seen = set(); cleaned = []
    for c in categories:
        if not c:
            continue
        if re.search(r"\barsenal\s*labs?\b", c, flags=re.I):
            continue
        if c not in seen:
            seen.add(c); cleaned.append(c)
    return cleaned or ["Uncategorized"]

def parse_schedule_to_index(html: str) -> Dict[str, List[str]]:
    """
    Return dict mapping multiple keys per title -> [categories].
    Keys used:
      - norm_key(title)
      - norm_key_relaxed(title)
      - to_anchor_slug(title)
    """
    if not html:
        return {}
    soup = BeautifulSoup(html, "html.parser")
    index: Dict[str, List[str]] = {}

    # Preferred container
    blocks = soup.select(".data-container")
    # Fallbacks
    if not blocks:
        # try parent divs of session titles
        title_candidates = soup.select(".session-title, .session-title a, [itemprop='summary'], [itemprop='summary'] a")
        for el in title_candidates:
            block = el
            for _ in range(5):
                if block is None:
                    break
                if getattr(block, "name", None) == "div":
                    break
                block = block.parent
            if block:
                blocks.append(block)

    for block in blocks:
        # Title inside the block
        title_el = (
            block.select_one(".session-title a") or
            block.select_one(".session-title") or
            block.select_one("[itemprop='summary'] a") or
            block.select_one("[itemprop='summary']") or
            block.find(["h1","h2"])
        )
        if not title_el:
            continue
        title = title_el.get_text(" ", strip=True)
        if not title:
            continue

        # Find a Track wrapper near this title
        wrapper = block.select_one(".list-view-filter-list-wrapper.session-track, .session-track")
        if not wrapper:
            sib = getattr(block, "next_sibling", None)
            hops = 0
            while sib and hops < 6 and not wrapper:
                if getattr(sib, "select_one", None):
                    wrapper = sib.select_one(".list-view-filter-list-wrapper.session-track, .session-track")
                sib = getattr(sib, "next_sibling", None)
                hops += 1
        if not wrapper:
            all_wrappers = soup.select(".list-view-filter-list-wrapper.session-track, .session-track")
            for w in all_wrappers:
                if w.find_previous(string=title):
                    wrapper = w
                    break

        categories = extract_categories_from_track_wrapper(wrapper)

        # Store under multiple keys
        keys = {norm_key(title), norm_key_relaxed(title), to_anchor_slug(title)}
        for k in keys:
            index[k] = categories

    return index

# -------------------- Category path rules --------------------
def build_category_path(base_outdir: str, category_label: str) -> str:
    if "/" in category_label:
        parts = [p.strip() for p in category_label.split("/") if p.strip()]
        safe_parts = [re.sub(r"[^A-Za-z0-9 \-\._]", "", p).strip() for p in parts]
        return os.path.join(base_outdir, *safe_parts)
    safe = re.sub(r"[^A-Za-z0-9]+", "_", category_label).strip("_")
    return os.path.join(base_outdir, safe)

# -------------------- Main --------------------
def main():
    ap = argparse.ArgumentParser(description="Merge local Arsenal MDs with categories from Black Hat schedule and write per-category Markdown files.")
    ap.add_argument("--root", default=".", help="Root of your BlackHat-Arsenal repo")
    ap.add_argument("--outdir", default="Categories", help="Output base folder (will create subfolders)")
    ap.add_argument("--unmatched-log", help="Optional CSV file to log titles that had no match")
    ap.add_argument("--dry-run", action="store_true", help="Do not write files; just print planned actions")
    args = ap.parse_args()

    md_files = find_md_files(args.root)
    if not md_files:
        print("No BlackHat MD files found (2022–2025).", file=sys.stderr)
        sys.exit(1)

    schedule_index_cache: Dict[Tuple[str, str], Dict[str, List[str]]] = {}
    planned = []
    unmatched_rows = []

    for md_path in tqdm(md_files, desc="MD files"):
        pr = parse_year_region_from_filename(md_path)
        if not pr:
            continue
        year, region = pr
        if region in SKIP_REGIONS:
            continue  # skip MEA entirely

        region_code = REGION_MAP.get(region.upper())
        if not region_code:
            continue
        yy = year[-2:]

        key = (region_code, yy)
        if key not in schedule_index_cache:
            url = f"https://www.blackhat.com/{region_code}-{yy}/arsenal/schedule/"
            html = fetch_schedule_rendered(url)
            if html is None:
                print(f"[warn] Could not fetch schedule (all methods failed): {url}", file=sys.stderr)
                schedule_index_cache[key] = {}
            else:
                schedule_index_cache[key] = parse_schedule_to_index(html)

        index = schedule_index_cache[key]

        for title, body_html in extract_tools_from_md(md_path):
            github = find_first_github_url(body_html)
            if not github:
                continue
            description = clean_description_from_details(body_html) or ""

            # Try multiple normalized keys for deterministic mapping
            keys = [norm_key(title), norm_key_relaxed(title), to_anchor_slug(title)]
            cats = None
            for k in keys:
                if k in index:
                    cats = index[k]
                    break
            if not cats:
                cats = ["Uncategorized"]
                if args.unmatched_log:
                    unmatched_rows.append({
                        "md_path": md_path,
                        "title": title,
                        "region": region,
                        "year": year
                    })

            primary = cats[0]
            cat_folder = build_category_path(args.outdir, primary)
            filename = slugify_filename(title) + ".md"
            out_path = os.path.join(cat_folder, filename)

            md_out = f"# {title}\n\n## Description\n{description}\n\n## Code\n{github}\n"

            if args.dry_run:
                planned.append(out_path)
            else:
                write_text(out_path, md_out)

    if args.dry_run:
        print("Planned writes:")
        for p in planned:
            print(" -", p)
    else:
        print("Done. Wrote categorized Markdown files to:", args.outdir)

    if args.unmatched_log:
        fieldnames = ["md_path", "title", "region", "year"]
        with open(args.unmatched_log, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for row in unmatched_rows:
                w.writerow(row)
        print(f"Wrote {len(unmatched_rows)} unmatched records to {args.unmatched_log}")
    else:
        if unmatched_rows:
            print(f"Unmatched titles: {len(unmatched_rows)}")
        else:
            print("All titles matched.")

if __name__ == "__main__":
    main()
