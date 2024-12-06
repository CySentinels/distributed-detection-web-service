import collections
import difflib
import re
import string
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

import dns.resolver
import requests
import tldextract
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Retry mechanism for HTTP requests
session = requests.Session()
retry_strategy = Retry(
    total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)


@lru_cache(maxsize=100)
def fetch_url_content(url):
    """Fetch URL content with retries and caching."""
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error for {url}: {http_err}")
        return None
    except requests.exceptions.RequestException as req_err:
        print(f"Request error for {url}: {req_err}")
        return None


def dns_query(domain, record_type):
    """Perform DNS queries for specific record types."""
    try:
        return dns.resolver.resolve(domain, record_type)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return []


def validate_domain(domain):
    """Check legitimacy with DNS queries (A, MX, NS records)."""
    a_records = dns_query(domain, "A")
    mx_records = dns_query(domain, "MX")
    ns_records = dns_query(domain, "NS")

    # Check if at least one record exists for each type
    is_valid = bool(a_records or mx_records or ns_records)
    return int(is_valid)  # Return 1 for valid, 0 otherwise


def similarity_score(a, b):
    """Compute similarity score using difflib."""
    return difflib.SequenceMatcher(None, a, b).ratio() * 100


def has_hidden_fields(soup):
    return bool(soup.find_all("input", type="hidden"))


def no_of_popups(soup):
    # Look for JavaScript functions that may indicate popups
    popup_patterns = re.compile(r"window\.open|alert\(|confirm\(|prompt\(")
    scripts = soup.find_all("script")
    return sum(1 for script in scripts if popup_patterns.search(script.get_text()))


def url_title_match_score(url, title):
    title_words = set(re.findall(r"\w+", title.lower()))
    url_words = set(re.findall(r"\w+", url.lower()))
    common_words = title_words & url_words
    return len(common_words) / len(title_words) if title_words else 0


def has_password_field(soup):
    return bool(soup.find_all("input", type="password"))


def has_copyright_info(soup):
    copyright_patterns = re.compile(r"©|&copy;|copyright", re.IGNORECASE)
    return bool(soup.find(text=copyright_patterns))


def no_of_self_redirects(soup, domain):
    links = soup.find_all("a", href=True)
    return sum(1 for link in links if domain in link["href"])


def no_of_iframes(soup):
    return len(soup.find_all("iframe"))


def obfuscation_ratio(html):
    total_chars = len(html)
    special_chars = sum(
        1 for c in html if not c.isalnum() and c not in string.whitespace
    )
    return special_chars / total_chars if total_chars else 0


def domain_title_match_score(domain, title):
    domain_parts = set(re.findall(r"\w+", domain.lower()))
    title_parts = set(re.findall(r"\w+", title.lower()))
    common_parts = domain_parts & title_parts
    return len(common_parts) / len(title_parts) if title_parts else 0


def url_char_prob(url):
    url_chars = re.sub(r"[^a-zA-Z]", "", url.lower())
    char_counts = collections.Counter(url_chars)
    total_chars = len(url_chars)
    return {char: count / total_chars for char, count in char_counts.items()}


def no_of_url_redirects(response):
    return len(response.history)


def has_submit_button(soup):
    return bool(soup.find("button", type="submit") or soup.find("input", type="submit"))


def has_external_form_submit(soup, domain):
    forms = soup.find_all("form")
    external_forms = [
        form for form in forms if form.get("action") and domain not in form["action"]
    ]
    return bool(external_forms)


def char_continuation_rate(url):
    consecutive = 0
    max_consecutive = 0
    for i in range(1, len(url)):
        if url[i].isalpha() and url[i] == url[i - 1]:
            consecutive += 1
            max_consecutive = max(max_consecutive, consecutive)
        else:
            consecutive = 0
    return max_consecutive / len(url) if len(url) else 0


def extract_features_v0(url):
    """Extract features from the given URL."""
    features = {}
    parsed_url = urllib.parse.urlparse(url)
    domain_info = tldextract.extract(url)
    domain = parsed_url.netloc

    # URL and domain analysis
    features["URLLength"] = len(url)
    features["DomainLength"] = len(domain_info.domain)
    features["TLDLength"] = len(domain_info.suffix)
    features["NoOfSubDomain"] = len(domain_info.subdomain.split("."))
    features["IsDomainIP"] = (
        1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain_info.domain) else 0
    )
    features["IsHTTPS"] = 1 if parsed_url.scheme == "https" else 0

    # Character counts in URL
    features["NoOfLettersInURL"] = sum(c.isalpha() for c in url)
    features["NoOfDegitsInURL"] = sum(c.isdigit() for c in url)
    features["NoOfEqualsInURL"] = url.count("=")
    features["NoOfQMarkInURL"] = url.count("?")
    features["NoOfAmpersandInURL"] = url.count("&")
    special_chars = re.findall(r"[^\w\s]", url)
    features["NoOfOtherSpecialCharsInURL"] = (
        len(special_chars) - features["NoOfQMarkInURL"] - features["NoOfAmpersandInURL"]
    )

    # Ratios
    url_length = len(url)
    features["LetterRatioInURL"] = features["NoOfLettersInURL"] / url_length
    features["DegitRatioInURL"] = features["NoOfDegitsInURL"] / url_length
    features["SpacialCharRatioInURL"] = len(special_chars) / url_length

    # TLD legitimacy and similarity scores
    features["TLDLegitimateProb"] = 0.5  # Placeholder value
    features["URLSimilarityIndex"] = similarity_score(
        domain_info.domain, parsed_url.path
    )

    # DNS-based domain legitimacy check
    features["IsDomainLegitimate"] = validate_domain(domain_info.domain)

    html = fetch_url_content(url)
    if html is None:
        print(f"Skipping {url} due to fetch error.")
        return features

    # HTML parsing with BeautifulSoup
    try:
        soup = BeautifulSoup(html, "html.parser")
        lines = html.splitlines()
        title = soup.title.string if soup.title else ""
        response = requests.get(url)  # Used to count redirects

        features["LineOfCode"] = len(lines)
        features["LargestLineLength"] = max(len(line) for line in lines)

        features["NoOfImage"] = len(soup.find_all("img"))
        features["NoOfCSS"] = len(soup.find_all("link", {"rel": "stylesheet"}))
        features["NoOfJS"] = len(soup.find_all("script"))

        all_links = soup.find_all("a")
        features["NoOfSelfRef"] = sum(
            1 for link in all_links if url in link.get("href", "")
        )
        features["NoOfEmptyRef"] = sum(
            1 for link in all_links if link.get("href") == "#"
        )
        features["NoOfExternalRef"] = (
            len(all_links) - features["NoOfSelfRef"] - features["NoOfEmptyRef"]
        )

        # Metadata checks
        features["HasTitle"] = 1 if soup.title else 0
        if soup.title:
            features["DomainTitleMatchScore"] = similarity_score(
                domain_info.domain, soup.title.text
            )
            features["URLTitleMatchScore"] = similarity_score(url, soup.title.text)

        features["HasFavicon"] = 1 if soup.find("link", rel="icon") else 0
        features["Robots"] = 1 if soup.find("meta", {"name": "robots"}) else 0
        features["IsResponsive"] = 1 if soup.find("meta", {"name": "viewport"}) else 0

        features["HasDescription"] = (
            1 if soup.find("meta", {"name": "description"}) else 0
        )
        features["HasSocialNet"] = any(
            net in html for net in ["facebook", "twitter", "instagram", "linkedin"]
        )
        features["HasHiddenFields"] = (has_hidden_fields(soup),)
        features["NoOfPopup"] = (no_of_popups(soup),)
        features["URLTitleMatchScore"] = (url_title_match_score(url, title),)
        features["HasPasswordField"] = (has_password_field(soup),)
        features["HasCopyrightInfo"] = (has_copyright_info(soup),)
        features["NoOfSelfRedirect"] = (no_of_self_redirects(soup, domain),)
        features["NoOfiFrame"] = (no_of_iframes(soup),)
        features["ObfuscationRatio"] = (obfuscation_ratio(html),)
        features["DomainTitleMatchScore"] = (domain_title_match_score(domain, title),)
        features["URLCharProb"] = (0.5,)  # Placeholder value
        features["NoOfURLRedirect"] = (no_of_url_redirects(response),)
        features["HasSubmitButton"] = (has_submit_button(soup),)
        features["HasExternalFormSubmit"] = (has_external_form_submit(soup, domain),)
        features["CharContinuationRate"] = char_continuation_rate(url)

    except Exception as e:
        print(f"Error parsing HTML content for {url}: {e}")

    return features


def extract_features(url):
    """Extract features from the given URL."""
    features = {}
    parsed_url = urllib.parse.urlparse(url)
    domain_info = tldextract.extract(url)
    domain = parsed_url.netloc

    # Basic URL features
    features["URLLength"] = len(url)
    # features['Domain'] = domain_info.domain
    features["DomainLength"] = len(domain_info.domain)
    features["IsDomainIP"] = (
        1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain_info.domain) else 0
    )
    features["TLD"] = domain_info.suffix
    features["TLDLength"] = len(domain_info.suffix)
    features["NoOfSubDomain"] = (
        len(domain_info.subdomain.split(".")) if domain_info.subdomain else 0
    )
    features["IsHTTPS"] = 1 if parsed_url.scheme == "https" else 0

    # URL character analysis
    features["NoOfLettersInURL"] = sum(c.isalpha() for c in url)
    features["NoOfDegitsInURL"] = sum(c.isdigit() for c in url)
    features["NoOfEqualsInURL"] = url.count("=")
    features["NoOfQMarkInURL"] = url.count("?")
    features["NoOfAmpersandInURL"] = url.count("&")
    special_chars = re.findall(r"[^\w\s]", url)
    features["NoOfOtherSpecialCharsInURL"] = (
        len(special_chars) - features["NoOfQMarkInURL"] - features["NoOfAmpersandInURL"]
    )

    # Ratios
    url_length = len(url)
    features["LetterRatioInURL"] = (
        features["NoOfLettersInURL"] / url_length if url_length > 0 else 0
    )
    features["DegitRatioInURL"] = (
        features["NoOfDegitsInURL"] / url_length if url_length > 0 else 0
    )
    features["SpacialCharRatioInURL"] = (
        len(special_chars) / url_length if url_length > 0 else 0
    )

    # Obfuscation analysis
    obfuscated_chars = re.findall(r"%[0-9a-fA-F]{2}", url)
    features["HasObfuscation"] = 1 if obfuscated_chars else 0
    features["NoOfObfuscatedChar"] = len(obfuscated_chars)
    features["ObfuscationRatio"] = (
        features["NoOfObfuscatedChar"] / url_length if url_length > 0 else 0
    )

    # URL similarity and continuation
    features["URLSimilarityIndex"] = similarity_score(
        domain_info.domain, parsed_url.path
    )
    features["CharContinuationRate"] = char_continuation_rate(url)
    features["URLCharProb"] = 0.9  # Placeholder - could be implemented
    features["TLDLegitimateProb"] = (
        0.9  # Placeholder - could be implemented with a TLD legitimacy database
    )

    html = fetch_url_content(url)
    if html is None:
        return features

    try:
        soup = BeautifulSoup(html, "html.parser")
        lines = html.splitlines()
        title = soup.title.string if soup.title else ""
        response = requests.get(url)

        # HTML content features
        # features['LineOfCode'] = len(lines)
        features["LargestLineLength"] = max(len(line) for line in lines)
        features["HasTitle"] = 1 if soup.title else 0
        features["DomainTitleMatchScore"] = domain_title_match_score(domain, title)
        features["URLTitleMatchScore"] = url_title_match_score(url, title)

        # Meta features
        features["HasFavicon"] = 1 if soup.find("link", rel="icon") else 0
        features["Robots"] = 1 if soup.find("meta", {"name": "robots"}) else 0
        features["IsResponsive"] = 1 if soup.find("meta", {"name": "viewport"}) else 0
        features["HasDescription"] = (
            1 if soup.find("meta", {"name": "description"}) else 0
        )

        # Resource counts
        # features['NoOfImage'] = len(soup.find_all('img'))
        features["NoOfCSS"] = len(soup.find_all("link", {"rel": "stylesheet"}))
        # features['NoOfJS'] = len(soup.find_all('script'))

        # Link analysis
        all_links = soup.find_all("a")
        features["NoOfSelfRef"] = sum(
            1 for link in all_links if url in link.get("href", "")
        )
        features["NoOfEmptyRef"] = sum(
            1 for link in all_links if link.get("href") == "#"
        )
        features["NoOfExternalRef"] = (
            len(all_links) - features["NoOfSelfRef"] - features["NoOfEmptyRef"]
        )

        # Security features
        features["NoOfURLRedirect"] = len(response.history)
        features["NoOfSelfRedirect"] = no_of_self_redirects(soup, domain)
        features["NoOfPopup"] = no_of_popups(soup)
        features["NoOfiFrame"] = no_of_iframes(soup)
        features["HasExternalFormSubmit"] = (
            1 if has_external_form_submit(soup, domain) else 0
        )
        features["HasSubmitButton"] = 1 if has_submit_button(soup) else 0
        features["HasHiddenFields"] = 1 if has_hidden_fields(soup) else 0
        features["HasPasswordField"] = 1 if has_password_field(soup) else 0
        features["HasCopyrightInfo"] = 1 if has_copyright_info(soup) else 0

        # Content analysis
        features["HasSocialNet"] = (
            1 if re.search(r"facebook|twitter|instagram|linkedin", html, re.I) else 0
        )
        features["Bank"] = (
            1 if re.search(r"bank|banking|credit|debit", html, re.I) else 0
        )
        features["Pay"] = 1 if re.search(r"payment|pay|transaction", html, re.I) else 0
        features["Crypto"] = (
            1 if re.search(r"crypto|bitcoin|ethereum|wallet", html, re.I) else 0
        )

    except Exception as e:
        print(f"Error parsing HTML content for {url}: {e}")

    return features


def process_urls_multithreaded(urls):
    """Process multiple URLs in parallel using ThreadPoolExecutor."""
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(extract_features, url): url for url in urls}
        results = []
        for future in as_completed(futures):
            url = futures[future]
            try:
                features = future.result()
                print(f"Features for {url}: {features}")
                results.append(features)
            except Exception as e:
                print(f"Error processing {url}: {e}")
    return results

def process_urls(urls):
    results = []
    for url in urls:
        try:
            features = extract_features(url)
            print(f"Features for {url}: {features}")
            results.append(features)
        except Exception as e:
            print(f"Error processing {url}: {e}")
    return results
