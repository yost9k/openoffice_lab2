CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(32) UNIQUE NOT NULL,
    vendor_release_date DATE NOT NULL,
    vendor_release_url TEXT NOT NULL,
    cve_url TEXT NOT NULL,
    published_date TIMESTAMP,
    updated_date TIMESTAMP,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cvss_metrics (
    id SERIAL PRIMARY KEY,
    vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    version VARCHAR(32) NOT NULL,
    score NUMERIC(3,1) NOT NULL,
    vector TEXT NOT NULL,
    severity VARCHAR(32) NOT NULL,
    UNIQUE(vulnerability_id, version, score, vector, severity)
);

CREATE TABLE IF NOT EXISTS cpe_entries (
    id SERIAL PRIMARY KEY,
    cpe_string TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerability_cpe (
    vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    cpe_id INTEGER NOT NULL REFERENCES cpe_entries(id) ON DELETE CASCADE,
    PRIMARY KEY (vulnerability_id, cpe_id)
);

CREATE TABLE IF NOT EXISTS cwe_entries (
    id SERIAL PRIMARY KEY,
    cwe_code VARCHAR(64) UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerability_cwe (
    vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    cwe_id INTEGER NOT NULL REFERENCES cwe_entries(id) ON DELETE CASCADE,
    PRIMARY KEY (vulnerability_id, cwe_id)
);
