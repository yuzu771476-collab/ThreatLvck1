import os
import base64
import ipaddress
import time

from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import tldextract

from dotenv import load_dotenv


# Load .env from the same folder as analyzer.py
load_dotenv(Path(__file__).resolve().parent / ".env")

VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Use tldextract's bundled suffix list to avoid first-run downloads.
DOMAIN_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


# --------------------------------------------------
# HELPER: STANDARD CHECK RESULT
# --------------------------------------------------

def make_check(status, value, explanation):
    return {
        "status": status,
        "value": value,
        "explanation": explanation,
        "reason": explanation
    }


# --------------------------------------------------
# 1. DOMAIN REGISTRATION AGE
# --------------------------------------------------

def get_domain_age(hostname):
    """Retrieve domain registration age using RDAP."""

    try:
        ipaddress.ip_address(hostname)

        return {
            "status": "UNKNOWN",
            "reason": "Registration age is not applicable to an IP address.",
            "age_days": None
        }

    except ValueError:
        pass

    try:
        response = requests.get(
            f"https://rdap.org/domain/{hostname}",
            headers={"Accept": "application/rdap+json"},
            timeout=12
        )

        if response.status_code != 200:
            return {
                "status": "UNKNOWN",
                "reason": (
                    f"RDAP lookup returned HTTP {response.status_code}. "
                    "Registration age could not be verified."
                ),
                "age_days": None
            }

        data = response.json()

        registration_date = next(
            (
                event.get("eventDate")
                for event in data.get("events", [])
                if event.get("eventAction", "").lower() == "registration"
            ),
            None
        )

        if not registration_date:
            return {
                "status": "UNKNOWN",
                "reason": (
                    "The domain registry did not provide a registration date."
                ),
                "age_days": None
            }

        registered = datetime.fromisoformat(
            registration_date.replace("Z", "+00:00")
        )

        if registered.tzinfo is None:
            registered = registered.replace(tzinfo=timezone.utc)

        age_days = (
            datetime.now(timezone.utc) - registered
        ).days

        if age_days < 0:
            return {
                "status": "UNKNOWN",
                "reason": "The registry returned an invalid registration date.",
                "age_days": None
            }

        if age_days < 30:
            return {
                "status": "WARNING",
                "reason": (
                    f"The domain is approximately {age_days} days old. "
                    "Recently registered domains deserve extra caution."
                ),
                "age_days": age_days
            }

        return {
            "status": "PASS",
            "reason": (
                f"The domain is approximately {age_days} days old. "
                "Domain age alone cannot guarantee safety."
            ),
            "age_days": age_days
        }

    except (
        requests.RequestException,
        ValueError,
        TypeError,
        AttributeError
    ) as error:
        return {
            "status": "UNKNOWN",
            "reason": f"Domain registration lookup failed: {error}",
            "age_days": None
        }


# --------------------------------------------------
# 2. VIRUSTOTAL STATISTICS
# --------------------------------------------------

def process_vt_stats(stats):
    """Convert VirusTotal statistics into a readable result."""

    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))

    value = (
        f"Malicious: {malicious} | "
        f"Suspicious: {suspicious} | "
        f"Harmless: {harmless} | "
        f"Undetected: {undetected}"
    )

    if malicious > 0:
        status = "WARNING"
        reason = (
            f"{malicious} security vendors flagged this URL as malicious. "
            f"{suspicious} additional vendors marked it suspicious. "
            "Avoid visiting this URL."
        )

    elif suspicious > 0:
        status = "WARNING"
        reason = (
            f"{suspicious} security vendors marked this URL suspicious. "
            "No malicious detections were reported. Treat it cautiously."
        )

    elif harmless + undetected > 0:
        status = "PASS"
        reason = (
            "No malicious or suspicious detections were reported in the "
            "available analysis. This does not guarantee the URL is safe."
        )

    else:
        status = "UNKNOWN"
        reason = "VirusTotal did not provide usable detection statistics."

    return {
        "status": status,
        "reason": reason,
        "value": value,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected
    }


# --------------------------------------------------
# 3. VIRUSTOTAL URL REPUTATION
# --------------------------------------------------

def vt_error(status, reason):
    """Return a consistent VirusTotal error result."""

    return {
        "status": status,
        "reason": reason,
        "value": reason,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0
    }


def check_virustotal(url):
    """
    Retrieve an existing VirusTotal report.
    If no report exists, submit the URL for analysis.
    """

    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return vt_error(
            "NOT CONNECTED",
            "VirusTotal API key was not found. Check your .env file."
        )

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    try:
        # Generate URL-safe Base64 identifier.
        url_id = base64.urlsafe_b64encode(
            url.encode("utf-8")
        ).decode("ascii").rstrip("=")

        # STEP 1: Retrieve an existing report.
        response = requests.get(
            f"{VT_BASE_URL}/urls/{url_id}",
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:
            attributes = response.json().get(
                "data", {}
            ).get("attributes", {})

            stats = attributes.get("last_analysis_stats", {})

            if stats:
                return process_vt_stats(stats)

            return vt_error(
                "UNKNOWN",
                "VirusTotal returned a report without detection statistics."
            )

        # STEP 2: Submit URL if no report exists.
        if response.status_code == 404:

            submit_response = requests.post(
                f"{VT_BASE_URL}/urls",
                headers=headers,
                data={"url": url},
                timeout=15
            )

            if submit_response.status_code == 429:
                return vt_error(
                    "RATE LIMITED",
                    "VirusTotal API rate limit reached. Try again later."
                )

            if submit_response.status_code in (401, 403):
                return vt_error(
                    "ERROR",
                    "VirusTotal rejected the API key or denied access."
                )

            submit_response.raise_for_status()

            analysis_id = submit_response.json().get(
                "data", {}
            ).get("id")

            if not analysis_id:
                return vt_error(
                    "ERROR",
                    "VirusTotal did not return an analysis ID."
                )

            # STEP 3: Poll the analysis for a short period.
            for attempt in range(5):

                time.sleep(2)

                analysis_response = requests.get(
                    f"{VT_BASE_URL}/analyses/{analysis_id}",
                    headers=headers,
                    timeout=15
                )

                if analysis_response.status_code == 429:
                    return vt_error(
                        "RATE LIMITED",
                        "VirusTotal API rate limit reached. Try again later."
                    )

                analysis_response.raise_for_status()

                analysis_data = analysis_response.json().get(
                    "data", {}
                )

                attributes = analysis_data.get("attributes", {})

                if attributes.get("status") == "completed":
                    stats = attributes.get("stats", {})

                    if stats:
                        return process_vt_stats(stats)

                    break

            return vt_error(
                "PENDING",
                (
                    "URL submitted successfully. VirusTotal analysis is "
                    "still processing. Scan again shortly."
                )
            )

        if response.status_code == 429:
            return vt_error(
                "RATE LIMITED",
                "VirusTotal API rate limit reached. Try again later."
            )

        if response.status_code in (401, 403):
            return vt_error(
                "ERROR",
                "VirusTotal rejected the API key or denied access."
            )

        response.raise_for_status()

        return vt_error(
            "UNKNOWN",
            "VirusTotal returned an unexpected response."
        )

    except requests.RequestException as error:
        return vt_error(
            "ERROR",
            f"VirusTotal connection failed: {error}"
        )

    except (
        ValueError,
        TypeError,
        AttributeError,
        KeyError
    ) as error:
        return vt_error(
            "ERROR",
            f"Could not read VirusTotal response: {error}"
        )


# --------------------------------------------------
# 4. MAIN URL ANALYZER
# --------------------------------------------------

def analyze_url(url):
    """Analyze URL characteristics and calculate a heuristic risk score."""

    url = (url or "").strip()

    if not url:
        return {
            "url": "",
            "risk_score": 0,
            "status": "INVALID URL",
            "findings": ["Enter a URL to start scanning."],
            "checks": {}
        }

    # Add HTTPS if no protocol is provided.
    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        # Validate port syntax.
        _ = parsed.port

        if (
            parsed.scheme.lower() not in ("http", "https")
            or not hostname
            or any(char.isspace() for char in url)
            or not hostname.strip(".")
        ):
            raise ValueError("Invalid URL")

    except ValueError:
        return {
            "url": url,
            "risk_score": 0,
            "status": "INVALID URL",
            "findings": ["Enter a valid HTTP or HTTPS URL."],
            "checks": {}
        }

    checks = {}
    score = 0

    # CHECK 1: URL LENGTH

    url_length = len(url)

    if url_length > 100:
        score += 10

        checks["length"] = make_check(
            "WARNING",
            f"{url_length} characters",
            (
                "The URL exceeds 100 characters. Long URLs can hide "
                "confusing paths, but length alone does not prove danger."
            )
        )

    else:
        checks["length"] = make_check(
            "PASS",
            f"{url_length} characters",
            (
                "The URL is within the 100-character threshold. "
                "Short URLs can still be malicious."
            )
        )

    # CHECK 2: IP ADDRESS

    try:
        ipaddress.ip_address(hostname)

        score += 15

        checks["ip"] = make_check(
            "WARNING",
            f"IP address detected: {hostname}",
            (
                "The hostname uses a direct IP address instead of "
                "a conventional domain. This can be suspicious, "
                "but is not proof of malicious activity."
            )
        )

    except ValueError:
        checks["ip"] = make_check(
            "PASS",
            f"Domain detected: {hostname}",
            (
                "The hostname is not a plain IP address. "
                "A domain name does not automatically mean a site is trustworthy."
            )
        )

    # CHECK 3: @ SYMBOL

    if "@" in parsed.netloc:
        score += 15

        checks["at"] = make_check(
            "WARNING",
            "@ symbol detected",
            (
                "An @ symbol appears in the URL authority. "
                "It can disguise the hostname a browser will visit."
            )
        )

    else:
        checks["at"] = make_check(
            "PASS",
            "No @ symbol detected",
            "No @ symbol was found in the URL authority."
        )

    # CHECK 4: HTTPS

    if parsed.scheme.lower() == "http":
        score += 5

        checks["https"] = make_check(
            "WARNING",
            "HTTP protocol",
            (
                "This URL uses HTTP, which does not encrypt the connection. "
                "Avoid sending sensitive information over untrusted HTTP."
            )
        )

    else:
        checks["https"] = make_check(
            "PASS",
            "HTTPS protocol",
            (
                "This URL uses HTTPS. It encrypts the connection when "
                "correctly configured, but does not prove a site is safe."
            )
        )

    # CHECK 5: DOMAIN AGE

    try:
        ipaddress.ip_address(hostname)
        registered_domain = None

    except ValueError:
        extracted = DOMAIN_EXTRACTOR(hostname)
        registered_domain = extracted.top_domain_under_public_suffix

    if registered_domain:
        age = get_domain_age(registered_domain)

    else:
        age = {
            "status": "UNKNOWN",
            "reason": "Could not identify the registered domain.",
            "age_days": None
        }

    if age["age_days"] is not None:
        age_value = f"Approximately {age['age_days']} days old"
    else:
        age_value = "Registration age unavailable"

    checks["age"] = make_check(
        age["status"],
        age_value,
        age["reason"]
    )

    if age["age_days"] is not None and age["age_days"] < 30:
        score += 10

    # CHECK 6: VIRUSTOTAL

    vt = check_virustotal(url)

    checks["virustotal"] = make_check(
        vt["status"],
        vt["value"],
        vt["reason"]
    )

    # Score only actual detections.
    if vt["malicious"] > 0:
        score += 40

    elif vt["suspicious"] > 0:
        score += 15

    # Keep score within 0-100.
    score = min(score, 100)

    # FINAL RISK CATEGORY

    if score >= 40:
        status = "HIGH RISK"

    elif score >= 15:
        status = "SUSPICIOUS"

    else:
        status = "LOWER RISK"

    # FINDINGS

    findings = [
        f"{name.upper()}: {item['reason']}"
        for name, item in checks.items()
        if item["status"] == "WARNING"
    ]

    if not findings:
        findings.append(
            "No configured warning patterns were detected. "
            "This does not guarantee the URL is safe."
        )

    return {
        "url": url,
        "risk_score": score,
        "status": status,
        "findings": findings,
        "checks": checks
    }