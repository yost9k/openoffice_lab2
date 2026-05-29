import argparse
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


BULLETIN_URL = "https://www.openoffice.org/security/bulletin.html"
DOWNLOADS_URL = "https://openoffice.apache.org/downloads.html"
CVE_API_URL = "https://cveawg.mitre.org/api/cve/{}"
CVE_ORG_URL = "https://www.cve.org/CVERecord?id={}"

CWE_API_URL = "https://cwe-api.mitre.org/api/v1/cwe/weakness/{}"
CWE_HTML_URL = "https://cwe.mitre.org/data/definitions/{}.html"

CACHE_DIR = Path(".cache")
CVE_CACHE_FILE = CACHE_DIR / "cve_cache.json"
CWE_CACHE_FILE = CACHE_DIR / "cwe_cache.json"
RELEASE_CACHE_FILE = CACHE_DIR / "openoffice_release_cache.json"

HEADERS = {
    "User-Agent": "openoffice-lab2-collector/2.0"
}

MAX_WORKERS = 8


def load_cache(path: Path) -> dict:
    if not path.exists():
        return {}

    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except Exception:
        return {}


def save_cache(path: Path, data: dict) -> None:
    CACHE_DIR.mkdir(exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)


def request_text(url: str, timeout: int = 25) -> str:
    response = requests.get(url, headers=HEADERS, timeout=timeout)
    response.raise_for_status()
    return response.text


def normalize_cve(year: str, number: str) -> str:
    return f"CVE-{year}-{number.zfill(4)}"


def expand_cve_ids(text: str) -> list[str]:
    result = []

    # Форматы вида CVE-2009-3301/2 или CVE-2007-4770/4771
    for match in re.finditer(r"CVE-(\d{4})-(\d{3,7})\s*/\s*(\d{1,7})", text):
        year, first_number, second_part = match.groups()

        result.append(normalize_cve(year, first_number))

        if len(second_part) < len(first_number):
            second_number = first_number[:-len(second_part)] + second_part
        else:
            second_number = second_part

        result.append(normalize_cve(year, second_number))

    # Обычные CVE-ID
    for year, number in re.findall(r"CVE-(\d{4})-(\d{3,7})", text):
        result.append(normalize_cve(year, number))

    seen = set()
    unique = []

    for cve_id in result:
        if cve_id not in seen:
            seen.add(cve_id)
            unique.append(cve_id)

    return unique


def parse_date_from_text(text: str) -> str | None:
    text = re.sub(r"\s+", " ", text)

    iso_match = re.search(r"\b(20\d{2}|19\d{2})-(\d{2})-(\d{2})\b", text)
    if iso_match:
        return iso_match.group(0)

    month_formats = [
        "%d %B %Y",
        "%a %d %B %Y",
        "%A %d %B %Y",
        "%B %d, %Y",
        "%B %d %Y",
    ]

    us_date_match = re.search(
        r"\b(January|February|March|April|May|June|July|August|September|October|November|December)"
        r"\s+\d{1,2},?\s+\d{4}\b",
        text,
    )

    if us_date_match:
        raw_date = us_date_match.group(0)
        for fmt in ["%B %d, %Y", "%B %d %Y"]:
            try:
                return datetime.strptime(raw_date, fmt).date().isoformat()
            except ValueError:
                continue

    date_match = re.search(
        r"\b(?:(Mon|Tue|Wed|Thu|Fri|Sat|Sun|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\s+)?"
        r"(\d{1,2}\s+"
        r"(January|February|March|April|May|June|July|August|September|October|November|December)"
        r"\s+\d{4})\b",
        text,
    )

    if not date_match:
        return None

    weekday = date_match.group(1)
    date_part = date_match.group(2)

    candidates = [date_part]
    if weekday:
        candidates.insert(0, f"{weekday} {date_part}")

    for candidate in candidates:
        for fmt in month_formats:
            try:
                return datetime.strptime(candidate, fmt).date().isoformat()
            except ValueError:
                continue

    return None


def build_release_blog_urls(version: str) -> list[str]:
    dash_version = version.replace(".", "-")
    underscore_version = version.replace(".", "_")
    compact_version = version.replace(".", "")

    return [
        f"https://openoffice.apache.org/blog/announcing-apache-openoffice-{dash_version}.html",
        f"https://blogs.apache.org/ooo/entry/announcing_apache_openoffice_{underscore_version}",
        f"https://blogs.apache.org/ooo/entry/announcing_apache_openoffice_{compact_version}",
    ]


def get_release_date_from_downloads_page(version: str) -> str | None:
    # Основной источник дат релизов без хардкода:
    # официальная страница Apache OpenOffice Downloads -> Release Archives.
    try:
        html = request_text(DOWNLOADS_URL)
    except Exception:
        return None

    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ", strip=True)

    pattern = (
        rf"Apache OpenOffice\s+{re.escape(version)}\s+"
        r"\(released(?:\s+on)?\s+"
        r"([A-Za-z]+\s+\d{1,2},?\s+\d{4})\)"
    )

    match = re.search(pattern, text)

    if not match:
        return None

    raw_date = match.group(1)

    for fmt in ["%B %d, %Y", "%B %d %Y"]:
        try:
            return datetime.strptime(raw_date, fmt).date().isoformat()
        except ValueError:
            continue

    return None


def get_release_date_from_blog(version: str) -> str | None:
    for url in build_release_blog_urls(version):
        try:
            html = request_text(url)
        except Exception:
            continue

        release_date = parse_date_from_text(BeautifulSoup(html, "html.parser").get_text(" ", strip=True))
        if release_date:
            return release_date

    return None


def get_release_date_from_archive(version: str) -> str | None:
    # Не словарь дат: берём дату из Apache Archive Directory.
    # Это fallback, если для старого релиза не нашлась страница announcement.
    url = f"https://archive.apache.org/dist/openoffice/{version}/source/"

    try:
        html = request_text(url)
    except Exception:
        return None

    pattern = rf"apache-openoffice-{re.escape(version)}[^<]*?\s+((?:19|20)\d{{2}}-\d{{2}}-\d{{2}})"
    match = re.search(pattern, html)

    if match:
        return match.group(1)

    return parse_date_from_text(BeautifulSoup(html, "html.parser").get_text(" ", strip=True))


def get_release_date(version: str, cache: dict) -> str:
    if version in cache:
        return cache[version]

    print(f"[*] Получаю дату релиза Apache OpenOffice {version}...")

    release_date = get_release_date_from_downloads_page(version)

    if not release_date:
        release_date = get_release_date_from_blog(version)

    if not release_date:
        release_date = get_release_date_from_archive(version)

    if not release_date:
        raise RuntimeError(f"Не удалось получить дату релиза Apache OpenOffice {version}")

    cache[version] = release_date
    save_cache(RELEASE_CACHE_FILE, cache)

    return release_date


def collect_bulletin_records() -> list[dict]:
    print("[*] Парсинг Apache OpenOffice Security Bulletin...")

    html = request_text(BULLETIN_URL)
    soup = BeautifulSoup(html, "html.parser")

    records = []
    current_version = None

    for element in soup.find_all(["h3", "li"]):
        text = element.get_text(" ", strip=True)

        if element.name == "h3":
            match = re.search(r"Fixed in Apache OpenOffice\s+([0-9.]+)", text)
            current_version = match.group(1) if match else None
            continue

        if element.name != "li" or not current_version:
            continue

        cve_ids = expand_cve_ids(text)

        if not cve_ids:
            continue

        link = element.find("a", href=True)
        vendor_url = urljoin(BULLETIN_URL, link["href"]) if link else BULLETIN_URL

        for cve_id in cve_ids:
            records.append({
                "ID": cve_id,
                "fixed_version": current_version,
                "vendor_release_url": vendor_url,
            })

    unique = {}
    for record in records:
        unique.setdefault(record["ID"], record)

    return list(unique.values())


def collect_task_1() -> list[dict]:
    print("[*] Задача 1: сбор CVE и дат релизов без захардкоженного словаря...")

    release_cache = load_cache(RELEASE_CACHE_FILE)
    records = collect_bulletin_records()

    versions = sorted({item["fixed_version"] for item in records})
    print(f"[*] Найдено версий релизов: {len(versions)}")

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(get_release_date, version, release_cache): version
            for version in versions
        }

        for future in as_completed(futures):
            version = futures[future]
            try:
                future.result()
            except Exception as error:
                print(f"[!] Ошибка при получении даты релиза {version}: {error}")

    result = []

    for item in records:
        version = item["fixed_version"]
        result.append({
            "ID": item["ID"],
            "fixed_version": version,
            "vendor_release_date": release_cache[version],
            "vendor_release_url": item["vendor_release_url"],
        })

    with open("result_task_1.json", "w", encoding="utf-8") as file:
        json.dump(result, file, indent=4, ensure_ascii=False)

    print(f"[+] Задача 1 готова. Найдено записей: {len(result)}")
    print("[+] Файл сохранен: result_task_1.json")

    return result


def get_containers(data: dict) -> list[dict]:
    containers = []

    cna = data.get("containers", {}).get("cna")
    if isinstance(cna, dict):
        containers.append(cna)

    adp = data.get("containers", {}).get("adp", [])
    if isinstance(adp, list):
        containers.extend([item for item in adp if isinstance(item, dict)])

    return containers


def extract_description(containers: list[dict]) -> str:
    for container in containers:
        descriptions = container.get("descriptions", [])
        for description in descriptions:
            value = description.get("value")
            if value:
                return value

    return "No description available"


def extract_cvss(containers: list[dict]) -> list[dict]:
    cvss_list = []

    for container in containers:
        for metric in container.get("metrics", []):
            for key, value in metric.items():
                if not key.lower().startswith("cvss") or not isinstance(value, dict):
                    continue

                version = (
                    key.replace("cvssV", "cvss")
                    .replace("_", "")
                    .replace(".", "")
                    .lower()
                )

                cvss_list.append({
                    "version": version,
                    "score": float(value.get("baseScore", 0.0)),
                    "vector": value.get("vectorString", "n/a"),
                    "severity": str(value.get("baseSeverity", "UNKNOWN")).upper(),
                })

    if not cvss_list:
        cvss_list.append({
            "version": "n/a",
            "score": 0.0,
            "vector": "n/a",
            "severity": "NONE",
        })

    unique = []
    seen = set()

    for item in cvss_list:
        key = (item["version"], item["score"], item["vector"], item["severity"])

        if key not in seen:
            seen.add(key)
            unique.append(item)

    return unique


def build_openoffice_cpe(version: str) -> str:
    version = version or "*"
    return f"cpe:2.3:a:apache:openoffice:{version}:*:*:*:*:*:*:*"


def normalize_openoffice_cpe(cpe: str, version: str) -> str:
    if not cpe.startswith("cpe:2.3:a:apache:openoffice:"):
        return cpe

    parts = cpe.split(":")

    if len(parts) > 5 and parts[5] in {"*", "-", "ANY", "NA"} and version:
        parts[5] = version
        return ":".join(parts)

    return cpe


def extract_version_from_text(text: str, fixed_version: str) -> str:
    patterns = [
        r"through\s+([0-9]+(?:\.[0-9]+)+)",
        r"versions?\s+([0-9]+(?:\.[0-9]+)+)\s+and older",
        r"version\s+([0-9]+(?:\.[0-9]+)+)\s+and older",
        r"prior to\s+([0-9]+(?:\.[0-9]+)+)",
        r"before\s+([0-9]+(?:\.[0-9]+)+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)

        if match:
            return match.group(1)

    return fixed_version


def extract_versions_from_affected(containers: list[dict]) -> list[str]:
    versions = []

    for container in containers:
        for affected in container.get("affected", []):
            for version_data in affected.get("versions", []):
                if not isinstance(version_data, dict):
                    continue

                for key in ["version", "lessThanOrEqual"]:
                    value = str(version_data.get(key, "")).strip()

                    if re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", value):
                        versions.append(value)

    return sorted(set(versions))


def extract_cpe(containers: list[dict], description: str, fixed_version: str) -> list[str]:
    cpe_list = []

    affected_versions = extract_versions_from_affected(containers)
    text_version = extract_version_from_text(description, fixed_version)

    version_for_fallback = affected_versions[0] if affected_versions else text_version

    for container in containers:
        for affected in container.get("affected", []):
            for cpe in affected.get("cpes", []):
                if isinstance(cpe, str) and cpe.startswith("cpe:"):
                    cpe_list.append(normalize_openoffice_cpe(cpe, version_for_fallback))

    # Если API не дал CPE — строим CPE на основе версии,
    # собранной на первом этапе / извлеченной из описания.
    if not cpe_list:
        cpe_list.append(build_openoffice_cpe(version_for_fallback))

    # Если API вернул CPE не для Apache OpenOffice, например CPE ОС/пакета,
    # дополнительно добавляем CPE самого продукта OpenOffice.
    has_openoffice_cpe = any(
        item.startswith("cpe:2.3:a:apache:openoffice:")
        for item in cpe_list
    )

    if not has_openoffice_cpe:
        cpe_list.append(build_openoffice_cpe(version_for_fallback))

    # Если API дал только общий CPE по продукту, добавляем конкретизированный.
    if any(
        item.startswith("cpe:2.3:a:apache:openoffice:*:")
        for item in cpe_list
    ):
        cpe_list.append(build_openoffice_cpe(version_for_fallback))

    return sorted(set(cpe_list))


def extract_cwe_ids(containers: list[dict]) -> list[str]:
    cwe_ids = []

    for container in containers:
        for problem_type in container.get("problemTypes", []):
            for description in problem_type.get("descriptions", []):
                values = [
                    description.get("cweId"),
                    description.get("description"),
                    description.get("value"),
                ]

                for value in values:
                    if not value:
                        continue

                    for cwe_id in re.findall(r"CWE-\d+", str(value)):
                        cwe_ids.append(cwe_id)

    seen = set()
    unique = []

    for cwe_id in cwe_ids:
        if cwe_id not in seen:
            seen.add(cwe_id)
            unique.append(cwe_id)

    return unique


def find_weakness_object(data):
    if isinstance(data, dict):
        if "Name" in data and "Description" in data:
            return data

        for value in data.values():
            result = find_weakness_object(value)
            if result:
                return result

    if isinstance(data, list):
        for item in data:
            result = find_weakness_object(item)
            if result:
                return result

    return None


def get_cwe_from_api(cwe_id: str) -> dict | None:
    numeric_id = cwe_id.replace("CWE-", "")

    try:
        response = requests.get(
            CWE_API_URL.format(numeric_id),
            headers=HEADERS,
            timeout=20,
        )

        if response.status_code != 200:
            return None

        data = response.json()
        weakness = find_weakness_object(data)

        if weakness:
            return {
                "name": weakness.get("Name", cwe_id),
                "description": weakness.get("Description", cwe_id),
            }

    except Exception:
        return None

    return None


def get_cwe_from_html(cwe_id: str) -> dict | None:
    numeric_id = cwe_id.replace("CWE-", "")

    try:
        html = request_text(CWE_HTML_URL.format(numeric_id))
    except Exception:
        return None

    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ", strip=True)

    title = soup.find("title")
    title_text = title.get_text(" ", strip=True) if title else ""

    name = cwe_id
    title_match = re.search(rf"{cwe_id}:\s*(.+?)(?:\s*\(|$)", title_text)

    if title_match:
        name = title_match.group(1).strip()

    desc_match = re.search(
        r"Description\s+(.*?)\s+(?:Extended Description|Relationships|Applicable Platforms|Common Consequences)",
        text,
        flags=re.IGNORECASE,
    )

    description = desc_match.group(1).strip() if desc_match else name

    return {
        "name": name,
        "description": description,
    }


def get_cwe_details(cwe_id: str, cwe_cache: dict) -> dict:
    if cwe_id in cwe_cache:
        return cwe_cache[cwe_id]

    print(f"[*] Запрашиваю CWE-данные для {cwe_id}...")

    details = get_cwe_from_api(cwe_id)

    if not details:
        details = get_cwe_from_html(cwe_id)

    if not details:
        details = {
            "name": cwe_id,
            "description": "No CWE description available",
        }

    cwe_cache[cwe_id] = details
    save_cache(CWE_CACHE_FILE, cwe_cache)

    return details


def extract_cwe(containers: list[dict], cwe_cache: dict) -> dict:
    cwe_ids = extract_cwe_ids(containers)

    if not cwe_ids:
        return {
            "None": {
                "name": "n/a",
                "description": "n/a",
            }
        }

    result = {}

    for cwe_id in cwe_ids:
        result[cwe_id] = get_cwe_details(cwe_id, cwe_cache)

    return result


def empty_details(cve_id: str, fallback_date: str, fixed_version: str) -> dict:
    return {
        "url": CVE_ORG_URL.format(cve_id),
        "published_date": f"{fallback_date}T00:00:00Z",
        "updated_date": f"{fallback_date}T00:00:00Z",
        "description": "No description available",
        "cvss_list": [
            {
                "version": "n/a",
                "score": 0.0,
                "vector": "n/a",
                "severity": "NONE",
            }
        ],
        "cpe_list": [
            build_openoffice_cpe(fixed_version)
        ],
        "cwe": {
            "None": {
                "name": "n/a",
                "description": "n/a",
            }
        },
    }


def fetch_cve_data(cve_id: str) -> dict | None:
    response = requests.get(
        CVE_API_URL.format(cve_id),
        headers=HEADERS,
        timeout=25,
    )

    if response.status_code != 200:
        return None

    return response.json()


def get_cve_details(item: dict, cve_cache: dict, cwe_cache: dict) -> dict:
    cve_id = item["ID"]
    fallback_date = item["vendor_release_date"]
    fixed_version = item.get("fixed_version", "")

    if cve_id in cve_cache:
        return cve_cache[cve_id]

    print(f"[*] Запрашиваю данные для {cve_id}...")

    try:
        data = fetch_cve_data(cve_id)
    except Exception as error:
        print(f"[!] Ошибка API для {cve_id}: {error}; ставлю заглушки")
        details = empty_details(cve_id, fallback_date, fixed_version)
        cve_cache[cve_id] = details
        save_cache(CVE_CACHE_FILE, cve_cache)
        return details

    if not data:
        print(f"[!] API не вернул данные для {cve_id}; ставлю заглушки")
        details = empty_details(cve_id, fallback_date, fixed_version)
        cve_cache[cve_id] = details
        save_cache(CVE_CACHE_FILE, cve_cache)
        return details

    containers = get_containers(data)
    metadata = data.get("cveMetadata", {})

    description = extract_description(containers)

    details = empty_details(cve_id, fallback_date, fixed_version)
    details.update({
        "published_date": metadata.get("datePublished") or details["published_date"],
        "updated_date": metadata.get("dateUpdated") or details["updated_date"],
        "description": description,
        "cvss_list": extract_cvss(containers),
        "cpe_list": extract_cpe(containers, description, fixed_version),
        "cwe": extract_cwe(containers, cwe_cache),
    })

    cve_cache[cve_id] = details
    save_cache(CVE_CACHE_FILE, cve_cache)

    return details


def collect_task_2() -> list[dict]:
    print("[*] Задача 2: параллельное обогащение данных через MITRE CVE API и CWE API...")

    try:
        with open("result_task_1.json", "r", encoding="utf-8") as file:
            task_1_data = json.load(file)
    except FileNotFoundError:
        print("[-] result_task_1.json не найден. Сначала запусти: python3 collector.py --task task1")
        return []

    cve_cache = load_cache(CVE_CACHE_FILE)
    cwe_cache = load_cache(CWE_CACHE_FILE)

    result_by_id = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(get_cve_details, item, cve_cache, cwe_cache): item
            for item in task_1_data
        }

        for future in as_completed(futures):
            item = futures[future]
            cve_id = item["ID"]

            try:
                details = future.result()
            except Exception as error:
                print(f"[!] Ошибка обработки {cve_id}: {error}; ставлю заглушки")
                details = empty_details(
                    cve_id,
                    item["vendor_release_date"],
                    item.get("fixed_version", ""),
                )

            full_item = item.copy()
            full_item.update(details)
            result_by_id[cve_id] = full_item

    result = [result_by_id[item["ID"]] for item in task_1_data]

    with open("result_task_2.json", "w", encoding="utf-8") as file:
        json.dump(result, file, indent=4, ensure_ascii=False)

    print(f"[+] Задача 2 готова. Обработано записей: {len(result)}")
    print("[+] Файл сохранен: result_task_2.json")

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--task",
        choices=["task1", "task2", "all"],
        required=True,
        help="Что запустить: task1, task2 или all",
    )

    args = parser.parse_args()

    started_at = time.time()

    if args.task == "task1":
        collect_task_1()
    elif args.task == "task2":
        collect_task_2()
    elif args.task == "all":
        collect_task_1()
        collect_task_2()

    elapsed = time.time() - started_at
    print(f"[+] Время выполнения: {elapsed:.2f} сек.")


if __name__ == "__main__":
    main()
