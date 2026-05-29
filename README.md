# Apache OpenOffice Vulnerability Analyzer & Loader

Проект представляет собой автоматизированный инструмент для сбора данных об уязвимостях Apache OpenOffice, их обработки, валидации и сохранения в реляционную базу данных PostgreSQL.

---

## Структура проекта

```text
collector.py — Сбор CVE со страницы Apache OpenOffice Security Bulletin, автоматическое получение дат релизов и обогащение данных через API MITRE/CWE (Задачи 1 и 2).
converter.py — Конвертация собранных данных из JSON в формат XML (Задача 3).
validate_task.py — Проверка JSON-файла на соответствие заданной схеме (Задача 4).
db_filler.py — ETL-скрипт для загрузки данных в PostgreSQL (Задача 5).
json_schema.json — Схема для валидации структуры данных.
init.sql — SQL-скрипт для инициализации БД и создания таблиц в 3-й нормальной форме.
Dockerfile & docker-compose.yml — Инфраструктура для развертывания проекта в контейнерах.
requirements.txt — Список внешних зависимостей Python.
```

---


## Запуск проекта

### 1. Подготовка и развертывание

Сборка образа приложения и запуск контейнеров БД и сервиса приложения:

```bash
docker compose up -d --build
```

---

### 2. Сбор данных

Запуск парсинга сайта Apache OpenOffice Security Bulletin и обогащения данных через API MITRE.

```bash
docker compose run --rm app python3 collector.py --task all
```

---

### 3. Обработка и валидация

Генерация XML-файла:

```bash
docker compose run --rm app python3 converter.py
```

Проверка корректности JSON-данных:

```bash
docker compose run --rm app python3 validate_task.py
```


---

### 4. Загрузка в базу данных

Скрипт автоматически распределит данные из JSON по таблицам БД:

```text
vulnerabilities
cvss_metrics
cpe_entries
vulnerability_cpe
cwe_entries
vulnerability_cwe
```

Команда запуска:

```bash
docker compose exec app python3 db_filler.py
```

---

## Проверка базы данных

Просмотр созданных таблиц:

```bash
docker compose exec db psql -U openoffice_user -d openoffice_vulnerabilities -c "\dt"
```

Проверка количества записей:

```bash
docker compose exec db psql -U openoffice_user -d openoffice_vulnerabilities -c "SELECT COUNT(*) FROM vulnerabilities;"
docker compose exec db psql -U openoffice_user -d openoffice_vulnerabilities -c "SELECT COUNT(*) FROM cvss_metrics;"
docker compose exec db psql -U openoffice_user -d openoffice_vulnerabilities -c "SELECT COUNT(*) FROM cpe_entries;"
docker compose exec db psql -U openoffice_user -d openoffice_vulnerabilities -c "SELECT COUNT(*) FROM cwe_entries;"
```

---

## Итоговые файлы

После выполнения проекта создаются:

```text
result_task_1.json
result_task_2.json
result_task_3.xml
```

