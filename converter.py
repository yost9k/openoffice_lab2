import json
from lxml import etree


INPUT_FILE = "result_task_2.json"
OUTPUT_FILE = "result_task_3.xml"


def add_text_element(parent, tag, value):
    element = etree.SubElement(parent, tag)
    element.text = "" if value is None else str(value)
    return element


def convert_json_to_xml():
    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    root = etree.Element("vulnerabilities")

    for item in data:
        vuln = etree.SubElement(root, "vulnerability")

        add_text_element(vuln, "ID", item.get("ID"))
        add_text_element(vuln, "vendor_release_date", item.get("vendor_release_date"))
        add_text_element(vuln, "vendor_release_url", item.get("vendor_release_url"))
        add_text_element(vuln, "url", item.get("url"))
        add_text_element(vuln, "published_date", item.get("published_date"))
        add_text_element(vuln, "updated_date", item.get("updated_date"))
        add_text_element(vuln, "description", item.get("description"))

        cvss_list = etree.SubElement(vuln, "cvss_list")
        for cvss in item.get("cvss_list", []):
            cvss_element = etree.SubElement(
                cvss_list,
                "cvss",
                version=str(cvss.get("version", "n/a")),
                score=str(cvss.get("score", 0.0)),
                severity=str(cvss.get("severity", "NONE")),
            )
            cvss_element.text = str(cvss.get("vector", "n/a"))

        cpe_list = etree.SubElement(vuln, "cpe_list")
        for cpe in item.get("cpe_list", []):
            add_text_element(cpe_list, "cpe", cpe)

        cwe_list = etree.SubElement(vuln, "cwe_list")
        for cwe_id, cwe_data in item.get("cwe", {}).items():
            cwe_element = etree.SubElement(
                cwe_list,
                "cwe",
                id=str(cwe_id),
                name=str(cwe_data.get("name", "n/a")),
            )
            cwe_element.text = str(cwe_data.get("description", "n/a"))

    tree = etree.ElementTree(root)
    tree.write(
        OUTPUT_FILE,
        pretty_print=True,
        xml_declaration=True,
        encoding="UTF-8",
    )

    print(f"[+] Задача 3: XML успешно сохранен в {OUTPUT_FILE}")
    print(f"[+] Записей в XML: {len(data)}")


if __name__ == "__main__":
    convert_json_to_xml()
