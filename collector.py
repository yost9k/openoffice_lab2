import argparse
import json
import re
import time
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


BULLETIN_URL = "https://www.openoffice.org/security/bulletin.html"
CVE_API_URL = "https://cveawg.mitre.org/api/cve/{}"
CVE_ORG_URL = "https://www.cve.org/CVERecord?id={}"

# Для OpenOffice в ТЗ берем дату релиза версии, в которой уязвимость исправлена.
RELEASE_DATES = {
    "4.1.16": "2025-11-10",
    "4.1.15": "2023-12-22",
    "4.1.14": "2023-02-27",
    "4.1.13": "2022-07-22",
    "4.1.11": "2021-10-06",
    "4.1.10": "2021-05-04",
    "4.1.8": "2020-11-10",
    "4.1.7": "2019-09-21",
    "4.1.6": "2018-11-18",
    "4.1.5": "2017-12-30",
    "4.1.4": "2017-10-19",
    "4.1.3": "2016-10-12",
    "4.1.2": "2015-10-28",
    "4.1.1": "2014-08-21",
    "4.0.0": "2013-07-23",
    "3.4.1": "2012-08-23",
    "3.4.0": "2012-05-08",
}


def normalize_cve(year: str, number: str) -> str:
    return f"CVE-{year}-{number.zfill(4)}"


def expand_cve_ids(text: str) -> list[str]:
    result = []

    # Форматы вида CVE-2009-3301/2 или CVE-2007-4770/4771
    for match in re.finditer(r"CVE-(\d{4})-(\d{3,7})\s*/\s*(\d{1,7})", text):
        year, first_number, second_part = match.groups()

        first_id = normalize_cve(year, first_number)
        result.append(first_id)

        if len(second_part) < len(first_number):
            second_number = first_number[:-len(second_part)] + second_part
        else:
            second_number = second_part

        result.append(normalize_cve(year, second_number))

    # Обычные CVE-ID
    for year, number in re.findall(r"CVE-(\d{4})-(\d{3,7})", text):
        result.append(normalize_cve(year, number))

    # Дедупликация с сохранением порядка
    seen = set()
    unique = []
    for cve_id in result:
        if cve_id not in seen:
            seen.add(cve_id)
            unique.append(cve_id)

    return unique


def collect_task_1() -> list[dict]:
    print("[*] Задача 1: парсинг Apache OpenOffice Security Bulletin...")

    response = requests.get(BULLETIN_URL, timeout=20)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")

    current_version = None
    collected = {}
    elements = soup.find_all(["h3", "li"])

    for element in elements:
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
        release_date = RELEASE_DATES.get(current_version, "1970-01-01")

        for cve_id in cve_ids:
            if cve_id not in collected:
                collected[cve_id] = {
                    "ID": cve_id,
                    "vendor_release_date": release_date,
                    "vendor_release_url": vendor_url,
                }

    result = list(collected.values())

    with open("result_task_1.json", "w", encoding="utf-8") as file:
        json.dump(result, file, indent=4, ensure_ascii=False)

    print(f"[+] Задача 1 готова. Найдено записей: {len(result)}")
    print("[+] Файл сохранен: result_task_1.json")

    return result


def empty_details(cve_id: str, fallback_date: str) -> dict:
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
        "cpe_list": ["cpe:2.3:a:apache:openoffice:*:*:*:*:*:*:*:*"],
        "cwe": {
            "None": {
                "name": "n/a",
                "description": "n/a",
            }
        },
    }


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


def extract_cpe(containers: list[dict]) -> list[str]:
    cpe_list = []

    for container in containers:
        for affected in container.get("affected", []):
            for cpe in affected.get("cpes", []):
                if isinstance(cpe, str) and cpe.startswith("cpe:"):
                    cpe_list.append(cpe)

    if not cpe_list:
        cpe_list.append("cpe:2.3:a:apache:openoffice:*:*:*:*:*:*:*:*")

    return sorted(set(cpe_list))


def extract_cwe(containers: list[dict]) -> dict:
    cwe = {}

    for container in containers:
        for problem_type in container.get("problemTypes", []):
            for description in problem_type.get("descriptions", []):
                text = description.get("description", "")
                cwe_id = description.get("cweId")

                if not cwe_id:
                    match = re.search(r"CWE-\d+", text)
                    cwe_id = match.group(0) if match else None

                if cwe_id:
                    cwe[cwe_id] = {
                        "name": text or cwe_id,
                        "description": text or cwe_id,
                    }

    if not cwe:
        cwe["None"] = {
            "name": "n/a",
            "description": "n/a",
        }

    return cwe


def get_cve_details(cve_id: str, fallback_date: str) -> dict:
    print(f"[*] Запрашиваю данные для {cve_id}...")

    headers = {"User-Agent": "openoffice-lab2-collector/1.0"}

    try:
        response = requests.get(CVE_API_URL.format(cve_id), headers=headers, timeout=20)
        if response.status_code != 200:
            print(f"[!] API вернул {response.status_code} для {cve_id}; ставлю заглушки")
            return empty_details(cve_id, fallback_date)

        data = response.json()
    except Exception as error:
        print(f"[!] Ошибка API для {cve_id}: {error}; ставлю заглушки")
        return empty_details(cve_id, fallback_date)

    containers = get_containers(data)
    metadata = data.get("cveMetadata", {})

    details = empty_details(cve_id, fallback_date)
    details.update({
        "published_date": metadata.get("datePublished") or details["published_date"],
        "updated_date": metadata.get("dateUpdated") or details["updated_date"],
        "description": extract_description(containers),
        "cvss_list": extract_cvss(containers),
        "cpe_list": extract_cpe(containers),
        "cwe": extract_cwe(containers),
    })

    return details


def collect_task_2() -> list[dict]:
    print("[*] Задача 2: обогащение данных через MITRE CVE API...")

    try:
        with open("result_task_1.json", "r", encoding="utf-8") as file:
            task_1_data = json.load(file)
    except FileNotFoundError:
        print("[-] result_task_1.json не найден. Сначала запусти: python3 collector.py --task1")
        return []

    result = []

    for item in task_1_data:
        cve_id = item["ID"]
        details = get_cve_details(cve_id, item["vendor_release_date"])

        full_item = item.copy()
        full_item.update(details)
        result.append(full_item)

        time.sleep(0.3)

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

    if args.task == "task1":
        collect_task_1()
    elif args.task == "task2":
        collect_task_2()
    elif args.task == "all":
        collect_task_1()
        collect_task_2()


if __name__ == "__main__":
    main()
