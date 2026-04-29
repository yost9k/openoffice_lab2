import json
from lxml import etree
from jsonschema import validate


JSON_FILE = "result_task_2.json"
SCHEMA_FILE = "json_schema.json"
XML_FILE = "result_task_3.xml"


def validate_json():
    with open(JSON_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    with open(SCHEMA_FILE, "r", encoding="utf-8") as file:
        schema = json.load(file)

    validate(instance=data, schema=schema)

    print("[+] JSON Validation (Task 4) пройдена успешно")
    print(f"[+] Записей в JSON: {len(data)}")

    return data


def validate_xml_consistency(json_data):
    tree = etree.parse(XML_FILE)
    root = tree.getroot()

    xml_items = root.findall("vulnerability")

    print()
    print("--- XML Data Consistency (Task 3) ---")
    print(f"[*] Записей в JSON: {len(json_data)}")
    print(f"[*] Записей в XML: {len(xml_items)}")

    if len(json_data) != len(xml_items):
        raise ValueError("Количество записей в JSON и XML не совпадает")

    first_json_id = json_data[0]["ID"]
    first_xml_id = xml_items[0].findtext("ID")

    if first_json_id != first_xml_id:
        raise ValueError("ID первой записи в JSON и XML не совпадает")

    print(f"[+] Целостность подтверждена. Первая запись: {first_json_id}")


def main():
    json_data = validate_json()
    validate_xml_consistency(json_data)
    print("[+] Проверка соответствия данных завершена успешно")


if __name__ == "__main__":
    main()
