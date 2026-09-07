#!/usr/bin/env python3

import json
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


NVD_API = (
    "https://services.nvd.nist.gov/rest/json/"
    "cves/2.0"
)

EXPLOIT_DB_BASE = (
    "https://www.exploit-db.com/exploits/"
)

APACHE_TOMCAT_SECURITY = (
    "https://tomcat.apache.org/security-9.html"
)


def now():
    return datetime.now(
        timezone.utc
    ).isoformat()


def normalize_version(text):
    if not text:
        return ""

    match = re.search(
        r"\d+(?:\.\d+)+(?:[-+._][A-Za-z0-9._-]+)?",
        str(text),
    )

    if match:
        return match.group(0)

    return ""


def version_tuple(value):
    numbers = re.findall(
        r"\d+",
        str(value),
    )

    if not numbers:
        return None

    return tuple(
        int(number)
        for number in numbers
    )


def compare_versions(left, right):
    left_tuple = version_tuple(left)
    right_tuple = version_tuple(right)

    if left_tuple is None or right_tuple is None:
        return None

    length = max(
        len(left_tuple),
        len(right_tuple),
    )

    left_tuple += (
        0,
    ) * (
        length
        - len(left_tuple)
    )

    right_tuple += (
        0,
    ) * (
        length
        - len(right_tuple)
    )

    if left_tuple < right_tuple:
        return -1

    if left_tuple > right_tuple:
        return 1

    return 0


def version_matches_range(
    version,
    match,
):
    observed = version_tuple(
        version
    )

    if observed is None:
        return None

    start_including = match.get(
        "versionStartIncluding"
    )

    start_excluding = match.get(
        "versionStartExcluding"
    )

    end_including = match.get(
        "versionEndIncluding"
    )

    end_excluding = match.get(
        "versionEndExcluding"
    )

    exact_versions = []

    criteria = str(
        match.get(
            "criteria",
            ""
        )
    )

    cpe_parts = criteria.split(
        ":"
    )

    if (
        len(cpe_parts) >= 6
        and cpe_parts[0] == "cpe"
        and cpe_parts[1] == "2.3"
    ):

        cpe_version = cpe_parts[5]

        if (
            cpe_version
            and cpe_version not in {
                "*",
                "-",
            }
            and not cpe_version.startswith(
                "\\"
            )
        ):
            exact_versions.append(
                cpe_version
            )

    # An exact-version CPE is authoritative.
    # If the observed version is not that exact
    # version, this CPE does NOT match.
    if exact_versions:

        for exact in exact_versions:

            comparison = compare_versions(
                version,
                exact,
            )

            if comparison is None:
                return None

            if comparison == 0:
                return True

        return False

    # No exact CPE version means we may have a
    # version range instead.

    has_range = any(
        (
            start_including,
            start_excluding,
            end_including,
            end_excluding,
        )
    )

    if not has_range:
        # Wildcard CPE with no version bounds:
        # product matches, but version applicability
        # cannot be proven.
        return None

    if start_including:

        result = compare_versions(
            version,
            start_including,
        )

        if result is None:
            return None

        if result < 0:
            return False

    if start_excluding:

        result = compare_versions(
            version,
            start_excluding,
        )

        if result is None:
            return None

        if result <= 0:
            return False

    if end_including:

        result = compare_versions(
            version,
            end_including,
        )

        if result is None:
            return None

        if result > 0:
            return False

    if end_excluding:

        result = compare_versions(
            version,
            end_excluding,
        )

        if result is None:
            return None

        if result >= 0:
            return False

    return True


def identify_product(version_text):
    text = str(
        version_text or ""
    ).lower()

    products = (
        (
            "apache tomcat",
            "apache",
            "tomcat",
        ),
        (
            "apache httpd",
            "apache",
            "http_server",
        ),
        (
            "openssh",
            "openbsd",
            "openssh",
        ),
        (
            "nginx",
            "f5",
            "nginx",
        ),
        (
            "openssl",
            "openssl",
            "openssl",
        ),
        (
            "vsftpd",
            "beasts",
            "vsftpd",
        ),
        (
            "proftpd",
            "proftpd",
            "proftpd",
        ),
        (
            "samba",
            "samba",
            "samba",
        ),
        (
            "wordpress",
            "wordpress",
            "wordpress",
        ),
        (
            "mysql",
            "oracle",
            "mysql",
        ),
        (
            "mariadb",
            "mariadb",
            "mariadb",
        ),
    )

    for phrase, vendor, product in products:

        if phrase in text:

            return {
                "name": phrase,
                "vendor": vendor,
                "product": product,
            }

    return {
        "name": "",
        "vendor": "",
        "product": "",
    }


def nvd_search(
    keyword,
    limit=20,
):
    params = urllib.parse.urlencode(
        {
            "keywordSearch": keyword,
            "resultsPerPage": limit,
        }
    )

    url = (
        NVD_API
        + "?"
        + params
    )

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "NEXUS-HTB-Research/2.0"
        },
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=30,
        ) as response:

            raw = response.read().decode(
                "utf-8"
            )

        return json.loads(
            raw
        )

    except (
        urllib.error.URLError,
        json.JSONDecodeError,
    ) as error:

        raise RuntimeError(
            f"NVD search failed: {error}"
        ) from error


def nvd_cve_detail(
    cve_id,
):
    params = urllib.parse.urlencode(
        {
            "cveId": cve_id,
        }
    )

    url = (
        NVD_API
        + "?"
        + params
    )

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "NEXUS-HTB-Research/2.0"
        },
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=30,
        ) as response:

            raw = response.read().decode(
                "utf-8"
            )

        data = json.loads(
            raw
        )

        vulnerabilities = data.get(
            "vulnerabilities",
            [],
        )

        if not vulnerabilities:
            return {}

        return vulnerabilities[0].get(
            "cve",
            {},
        )

    except (
        urllib.error.URLError,
        json.JSONDecodeError,
    ) as error:

        raise RuntimeError(
            f"NVD CVE lookup failed for {cve_id}: {error}"
        ) from error


def extract_descriptions(cve):
    for item in cve.get(
        "descriptions",
        [],
    ):

        if item.get(
            "lang"
        ) == "en":

            return item.get(
                "value",
                "",
            )

    return ""


def extract_cvss(cve):
    metrics = cve.get(
        "metrics",
        {},
    )

    for metric_name in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):

        metric_items = metrics.get(
            metric_name,
            [],
        )

        if metric_items:

            cvss_data = metric_items[0].get(
                "cvssData",
                {},
            )

            return cvss_data.get(
                "baseScore"
            )

    return None


def iter_cpe_matches(node):
    if not isinstance(
        node,
        dict,
    ):
        return

    for match in node.get(
        "cpeMatch",
        [],
    ):

        if isinstance(
            match,
            dict,
        ):
            yield match

    for child in node.get(
        "children",
        [],
    ):

        yield from iter_cpe_matches(
            child
        )


def cpe_matches_product(
    criteria,
    product_info,
):
    parts = str(
        criteria
    ).split(":")

    if len(parts) < 6:
        return False

    if (
        parts[0] != "cpe"
        or parts[1] != "2.3"
    ):
        return False

    vendor = parts[3].lower()
    product = parts[4].lower()

    expected_vendor = product_info.get(
        "vendor",
        "",
    ).lower()

    expected_product = product_info.get(
        "product",
        "",
    ).lower()

    return (
        (
            not expected_vendor
            or vendor == expected_vendor
        )
        and
        (
            not expected_product
            or product == expected_product
        )
    )


def match_cve_to_service(
    cve,
    version,
    product_info,
):
    configurations = cve.get(
        "configurations",
        [],
    )

    found_product = False
    unknown_version = False

    for configuration in configurations:

        nodes = configuration.get(
            "nodes",
            [],
        )

        for node in nodes:

            for match in iter_cpe_matches(
                node
            ):

                criteria = match.get(
                    "criteria",
                    "",
                )

                if not cpe_matches_product(
                    criteria,
                    product_info,
                ):
                    continue

                found_product = True

                status = match.get(
                    "vulnerable",
                    True,
                )

                if not status:
                    continue

                result = version_matches_range(
                    version,
                    match,
                )

                if result is True:
                    return "MATCH"

                if result is None:
                    unknown_version = True

    if found_product and unknown_version:
        return "POSSIBLE"

    return "NO_MATCH"


def searchsploit(
    product,
    version,
):
    executable = shutil.which(
        "searchsploit"
    )

    if not executable:
        return {
            "available": False,
            "results": [],
            "message": (
                "SearchSploit is not installed."
            ),
        }

    query_parts = []

    if product:
        query_parts.append(
            product
        )

    if version:
        query_parts.append(
            version
        )

    query = " ".join(
        query_parts
    ).strip()

    if not query:
        return {
            "available": True,
            "results": [],
            "message": "No searchable product/version.",
        }

    try:

        completed = subprocess.run(
            [
                executable,
                "-j",
                "-t",
                "--disable-colour",
                query,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    except (
        OSError,
        subprocess.TimeoutExpired,
    ) as error:

        return {
            "available": True,
            "results": [],
            "message": (
                f"SearchSploit failed: {error}"
            ),
        }

    output = completed.stdout.strip()

    if not output:
        return {
            "available": True,
            "results": [],
            "message": (
                completed.stderr.strip()
                or "No SearchSploit results."
            ),
        }

    try:
        data = json.loads(
            output
        )

    except json.JSONDecodeError:

        return {
            "available": True,
            "results": [],
            "message": (
                "SearchSploit returned non-JSON output."
            ),
        }

    results = []

    for exploit in data.get(
        "RESULTS_EXPLOIT",
        [],
    ):

        edb_id = exploit.get(
            "EDB-ID"
        )

        title = exploit.get(
            "Title",
            "",
        )

        path = exploit.get(
            "Path",
            "",
        )

        results.append(
            {
                "edb_id": edb_id,
                "title": title,
                "path": path,
                "url": (
                    EXPLOIT_DB_BASE
                    + str(edb_id)
                )
                if edb_id
                else None,
                "source": "Exploit-DB",
            }
        )

    return {
        "available": True,
        "results": results,
        "message": (
            f"{len(results)} SearchSploit result(s)."
        ),
    }




def exploit_db_search_cve(cve_id):
    """
    Search the public Exploit-DB index by CVE.

    Exploit-DB maintains a structured files_exploits.csv
    index in its official repository. NEXUS downloads
    that metadata file and searches the CVE field.

    Only exploit metadata is returned. NEXUS does not
    download or execute exploit code.
    """

    cve_value = str(
        cve_id or ""
    ).upper()

    if not re.fullmatch(
        r"CVE-\d{4}-\d{4,}",
        cve_value,
    ):
        return {
            "available": False,
            "results": [],
            "message": "Invalid CVE identifier.",
        }

    csv_url = (
        "https://gitlab.com/"
        "exploit-database/exploitdb/"
        "-/raw/main/files_exploits.csv"
    )

    request = urllib.request.Request(
        csv_url,
        headers={
            "User-Agent": (
                "NEXUS-HTB-Research/2.0"
            )
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=30,
        ) as response:

            raw = response.read().decode(
                "utf-8",
                errors="replace",
            )

    except (
        urllib.error.URLError,
        TimeoutError,
    ) as error:

        return {
            "available": True,
            "results": [],
            "message": (
                f"Exploit-DB index request failed: {error}"
            ),
        }

    import csv
    import io

    results = []

    try:
        reader = csv.DictReader(
            io.StringIO(
                raw
            )
        )

        for row in reader:

            cves = str(
                row.get(
                    "codes",
                    ""
                )
                or row.get(
                    "CVE",
                    ""
                )
                or ""
            ).upper()

            cve_tokens = re.findall(
                r"CVE-\d{4}-\d{4,}",
                cves,
            )

            if cve_value not in cve_tokens:
                continue

            edb_id = (
                row.get("id")
                or row.get("EDB-ID")
                or row.get("edb-id")
            )

            title = (
                row.get("description")
                or row.get("title")
                or ""
            ).strip()

            date_published = (
                row.get("date_published")
                or row.get("date")
                or ""
            )

            author = (
                row.get("author")
                or ""
            ).strip()

            item_type = (
                row.get("type")
                or ""
            ).strip()

            platform = (
                row.get("platform")
                or ""
            ).strip()

            path_value = (
                row.get("file")
                or row.get("path")
                or ""
            ).strip()

            result = {
                "edb_id": (
                    int(edb_id)
                    if str(edb_id).isdigit()
                    else edb_id
                ),
                "title": title,
                "author": author,
                "type": item_type,
                "platform": platform,
                "date_published": date_published,
                "path": path_value,
                "source": "Exploit-DB",
                "url": (
                    "https://www.exploit-db.com/exploits/"
                    + str(edb_id)
                )
                if edb_id
                else None,
            }

            if result not in results:
                results.append(
                    result
                )

    except csv.Error as error:

        return {
            "available": True,
            "results": [],
            "message": (
                f"Exploit-DB CSV parsing failed: {error}"
            ),
        }

    return {
        "available": True,
        "results": results,
        "message": (
            f"{len(results)} Exploit-DB result(s)."
        ),
        "source_url": csv_url,
    }

def assess_exploitability(description):
    """
    Separate version applicability from exploitability.

    MATCH means the observed software version falls
    inside the affected-version range.

    Exploitability remains UNCONFIRMED until required
    configuration, platform, or deployment conditions
    are verified.
    """

    text = str(
        description or ""
    ).strip()

    lower = text.lower()

    conditions = []

    condition_patterns = (
        (
            "case insensitive file system",
            "case-insensitive file system",
        ),
        (
            "default servlet write enabled",
            "default servlet write enabled",
        ),
        (
            "writes enabled for the default servlet",
            "default servlet write enabled",
        ),
        (
            "support for partial put",
            "partial PUT support",
        ),
        (
            "file based session persistence",
            "file-based session persistence",
        ),
        (
            "custom jakarta authentication",
            "custom Jakarta Authentication component",
        ),
        (
            "jaspi",
            "custom JASPIC/Jakarta Authentication configuration",
        ),
        (
            "reverse proxy",
            "reverse proxy",
        ),
        (
            "rejectillegalheader",
            "rejectIllegalHeader configuration",
        ),
        (
            "http/2",
            "HTTP/2",
        ),
        (
            "websocket",
            "WebSocket functionality",
        ),
        (
            "rewrite valve",
            "Rewrite Valve configuration",
        ),
        (
            "preresources",
            "PreResources configuration",
        ),
        (
            "postresources",
            "PostResources configuration",
        ),
        (
            "cgi servlet",
            "CGI servlet configuration",
        ),
        (
            "apr/native",
            "APR/Native connector",
        ),
        (
            "tls configuration",
            "TLS configuration",
        ),
        (
            "client certificate authentication",
            "client certificate authentication",
        ),
        (
            "windows operating system",
            "Windows operating system",
        ),
        (
            "windows",
            "Windows environment",
        ),
        (
            "root (default) web application",
            "ROOT/default web application",
        ),
        (
            "examples web application",
            "examples web application",
        ),
    )

    for needle, label in condition_patterns:
        if needle in lower and label not in conditions:
            conditions.append(label)

    explicit_condition_markers = (
        "if ",
        "when ",
        "only applies if",
        "only when",
        "under certain configurations",
        "for a subset of",
        "when using",
        "provided that",
        "requires ",
    )

    explicit_condition = any(
        marker in lower
        for marker in explicit_condition_markers
    )

    platform = "UNSPECIFIED"

    if "windows" in lower:
        platform = "WINDOWS"

    if (
        "linux" in lower
        or "unix" in lower
        or "linux-based" in lower
    ):
        if platform == "UNSPECIFIED":
            platform = "UNIX_LIKE"
        else:
            platform = "MULTI_PLATFORM"

    if conditions or explicit_condition:
        if platform != "UNSPECIFIED":
            requirement = (
                "CONFIGURATION_OR_PLATFORM_REQUIRED"
            )
        else:
            requirement = "CONFIGURATION_REQUIRED"

        reason = (
            "The vulnerability is version-applicable, "
            "but the NVD description identifies additional "
            "configuration, deployment, application, or "
            "platform conditions that must be verified."
        )
    else:
        requirement = "NONE_STATED"

        reason = (
            "The NVD description does not identify a "
            "specific prerequisite that can be extracted "
            "automatically. Version applicability alone "
            "does not prove exploitability."
        )

    # Always return the same schema.
    return {
        "status": "UNCONFIRMED",
        "requirement": requirement,
        "platform": platform,
        "conditions": conditions,
        "reason": reason,
    }


def normalize_evidence_condition(
    value,
):
    """
    Normalize an evidence statement into a stable
    condition key.

    Example:
        "default servlet write enabled"
        ->
        "default_servlet_write_enabled"
    """

    value = str(
        value or ""
    ).strip().lower()

    value = re.sub(
        r"[^a-z0-9]+",
        "_",
        value,
    )

    return value.strip("_")


def condition_matches_evidence(
    condition,
    evidence,
):
    """
    Determine whether an extracted CVE condition is
    confirmed, contradicted, or still unknown.

    Returns:
        VERIFIED
        NOT_VERIFIED
        UNKNOWN
    """

    condition_key = normalize_evidence_condition(
        condition
    )

    evidence_items = (
        evidence
        if isinstance(
            evidence,
            list,
        )
        else []
    )

    for item in evidence_items:

        if not isinstance(
            item,
            dict,
        ):
            continue

        evidence_key = normalize_evidence_condition(
            item.get(
                "condition",
                "",
            )
        )

        if not evidence_key:
            continue

        if (
            evidence_key == condition_key
            or evidence_key in condition_key
            or condition_key in evidence_key
        ):

            status = str(
                item.get(
                    "status",
                    "UNKNOWN",
                )
            ).upper()

            if status in {
                "VERIFIED",
                "NOT_VERIFIED",
            }:
                return status

    return "UNKNOWN"


def assess_condition_evidence(
    conditions,
    evidence,
):
    """
    Compare CVE prerequisites against explicit
    operator-provided evidence.

    No evidence is treated as UNKNOWN, never false.
    """

    conditions = (
        conditions
        if isinstance(
            conditions,
            list,
        )
        else []
    )

    results = []

    verified = 0
    not_verified = 0
    unknown = 0

    for condition in conditions:

        status = condition_matches_evidence(
            condition,
            evidence,
        )

        if status == "VERIFIED":
            verified += 1

        elif status == "NOT_VERIFIED":
            not_verified += 1

        else:
            unknown += 1

        results.append(
            {
                "condition": condition,
                "status": status,
            }
        )

    total = len(
        results
    )

    if total == 0:

        assessment = (
            "UNCONFIRMED"
        )

    elif not_verified > 0:

        assessment = (
            "NOT_CURRENTLY_SUPPORTED"
        )

    elif unknown == 0:

        assessment = (
            "POSSIBLE"
        )

    else:

        assessment = (
            "UNCONFIRMED"
        )

    return {
        "assessment": assessment,
        "total": total,
        "verified": verified,
        "not_verified": not_verified,
        "unknown": unknown,
        "conditions": results,
    }


def research_service(
    service,
    evidence=None,
):
    version_text = service.get(
        "version",
        "",
    )

    version = normalize_version(
        version_text
    )

    product_info = identify_product(
        version_text
    )

    product_name = product_info.get(
        "name",
        "",
    )

    evidence = (
        evidence
        if isinstance(
            evidence,
            list,
        )
        else []
    )

    # Search using product + major/minor version.
    if product_name and version:

        version_parts = version.split(
            "."
        )

        if len(version_parts) >= 2:

            query = (
                f"{product_name} "
                f"{version_parts[0]}."
                f"{version_parts[1]}"
            )

        else:

            query = (
                f"{product_name} "
                f"{version_parts[0]}"
            )

    elif product_name:

        query = product_name

    else:

        query = version_text

    search_data = nvd_search(
        query,
        limit=100,
    )

    results = []

    for item in search_data.get(
        "vulnerabilities",
        [],
    ):

        cve = item.get(
            "cve",
            {},
        )

        cve_id = cve.get(
            "id"
        )

        if not cve_id:
            continue

        match_status = match_cve_to_service(
            cve,
            version,
            product_info,
        )

        if match_status == "NO_MATCH":
            continue

        description = extract_descriptions(
            cve
        )

        exploitability = assess_exploitability(
            description
        )

        evidence_assessment = (
            assess_condition_evidence(
                exploitability.get(
                    "conditions",
                    [],
                ),
                evidence,
            )
        )

        exploit_db = exploit_db_search_cve(
            cve_id
        )

        results.append(
            {
                "cve": cve_id,

                "match_status": match_status,

                "version_status": "AFFECTED",

                "exploitability_status": (
                    exploitability["status"]
                ),

                "requirement": (
                    exploitability["requirement"]
                ),

                "platform": (
                    exploitability["platform"]
                ),

                "conditions": (
                    exploitability["conditions"]
                ),

                "evidence_assessment": (
                    evidence_assessment
                ),

                "exploitability_reason": (
                    exploitability["reason"]
                ),

                "description": description,

                "cvss": extract_cvss(
                    cve
                ),

                "source": "NVD",

                "url": (
                    "https://nvd.nist.gov/vuln/detail/"
                    + str(cve_id)
                ),

                "exploit_db": exploit_db,
            }
        )

    status_order = {
        "MATCH": 0,
        "POSSIBLE": 1,
    }

    results.sort(
        key=lambda item: (
            status_order.get(
                item.get(
                    "match_status"
                ),
                99,
            ),
            -(
                float(
                    item.get(
                        "cvss"
                    )
                    or 0
                )
            ),
            item.get(
                "cve",
                "",
            ),
        )
    )

    return {
        "timestamp": now(),
        "port": service.get(
            "port"
        ),
        "protocol": service.get(
            "protocol"
        ),
        "service": service.get(
            "service"
        ),
        "product": product_info,
        "version": version,
        "query": query,
        "evidence_used": evidence,
        "nvd_results": results,
        "searchsploit": {
            "available": False,
            "results": [],
            "message": (
                "SearchSploit is not installed."
            ),
        },
        "vendor_security_reference": (
            APACHE_TOMCAT_SECURITY
            if product_name == "apache tomcat"
            else None
        ),
    }


if __name__ == "__main__":

    service = {
        "port": 8080,
        "protocol": "tcp",
        "service": "http",
        "version": "Apache Tomcat 9.0.65",
    }

    result = research_service(
        service
    )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )
