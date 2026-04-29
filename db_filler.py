import json
import os
import time
from datetime import date, datetime

import psycopg2


JSON_FILE = "result_task_2.json"


def parse_date(value):
    try:
        return date.fromisoformat(str(value)[:10])
    except Exception:
        return date(1970, 1, 1)


def parse_timestamp(value):
    if not value:
        return None

    value = str(value).replace("Z", "+00:00")

    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def connect_db():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "db"),
        dbname=os.getenv("DB_NAME", "openoffice_vulnerabilities"),
        user=os.getenv("DB_USER", "openoffice_user"),
        password=os.getenv("DB_PASSWORD", "password"),
    )


def wait_for_db():
    for _ in range(30):
        try:
            return connect_db()
        except psycopg2.OperationalError:
            print("[*] Ожидаю запуск PostgreSQL...")
            time.sleep(2)

    raise RuntimeError("PostgreSQL не запустился")


def insert_vulnerability(cursor, item):
    cursor.execute(
        """
        INSERT INTO vulnerabilities (
            cve_id,
            vendor_release_date,
            vendor_release_url,
            cve_url,
            published_date,
            updated_date,
            description
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (cve_id) DO UPDATE SET
            vendor_release_date = EXCLUDED.vendor_release_date,
            vendor_release_url = EXCLUDED.vendor_release_url,
            cve_url = EXCLUDED.cve_url,
            published_date = EXCLUDED.published_date,
            updated_date = EXCLUDED.updated_date,
            description = EXCLUDED.description
        RETURNING id;
        """,
        (
            item["ID"],
            parse_date(item["vendor_release_date"]),
            item["vendor_release_url"],
            item["url"],
            parse_timestamp(item["published_date"]),
            parse_timestamp(item["updated_date"]),
            item["description"],
        ),
    )

    return cursor.fetchone()[0]


def insert_cvss(cursor, vulnerability_id, cvss_list):
    for cvss in cvss_list:
        cursor.execute(
            """
            INSERT INTO cvss_metrics (
                vulnerability_id,
                version,
                score,
                vector,
                severity
            )
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING;
            """,
            (
                vulnerability_id,
                str(cvss.get("version", "n/a")),
                float(cvss.get("score", 0.0)),
                str(cvss.get("vector", "n/a")),
                str(cvss.get("severity", "NONE")),
            ),
        )


def insert_cpe(cursor, vulnerability_id, cpe_list):
    for cpe in cpe_list:
        cursor.execute(
            """
            INSERT INTO cpe_entries (cpe_string)
            VALUES (%s)
            ON CONFLICT (cpe_string) DO UPDATE SET
                cpe_string = EXCLUDED.cpe_string
            RETURNING id;
            """,
            (cpe,),
        )

        cpe_id = cursor.fetchone()[0]

        cursor.execute(
            """
            INSERT INTO vulnerability_cpe (vulnerability_id, cpe_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING;
            """,
            (vulnerability_id, cpe_id),
        )


def insert_cwe(cursor, vulnerability_id, cwe_data):
    for cwe_code, info in cwe_data.items():
        cursor.execute(
            """
            INSERT INTO cwe_entries (cwe_code, name, description)
            VALUES (%s, %s, %s)
            ON CONFLICT (cwe_code) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description
            RETURNING id;
            """,
            (
                str(cwe_code),
                str(info.get("name", "n/a")),
                str(info.get("description", "n/a")),
            ),
        )

        cwe_id = cursor.fetchone()[0]

        cursor.execute(
            """
            INSERT INTO vulnerability_cwe (vulnerability_id, cwe_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING;
            """,
            (vulnerability_id, cwe_id),
        )


def print_counts(cursor):
    tables = [
        "vulnerabilities",
        "cvss_metrics",
        "cpe_entries",
        "vulnerability_cpe",
        "cwe_entries",
        "vulnerability_cwe",
    ]

    print()
    print("--- DB counts ---")

    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table};")
        count = cursor.fetchone()[0]
        print(f"{table}: {count}")


def main():
    with open(JSON_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    conn = wait_for_db()

    try:
        with conn:
            with conn.cursor() as cursor:
                for item in data:
                    vulnerability_id = insert_vulnerability(cursor, item)
                    insert_cvss(cursor, vulnerability_id, item.get("cvss_list", []))
                    insert_cpe(cursor, vulnerability_id, item.get("cpe_list", []))
                    insert_cwe(cursor, vulnerability_id, item.get("cwe", {}))

                print(f"[+] База данных успешно заполнена. Обработано записей: {len(data)}")
                print_counts(cursor)

    finally:
        conn.close()


if __name__ == "__main__":
    main()
