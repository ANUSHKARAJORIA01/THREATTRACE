"""
database.py
------------
SQLite persistence layer for the AI Forensic Platform.

Provides reusable functions to initialize the database schema and to
insert / query records for investigations and each evidence type
(email, network, document, geolocation, generic evidence).

The database file is created automatically on first import/use.
"""

import sqlite3
import os
from datetime import datetime
from contextlib import contextmanager

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.path.join(DB_DIR, "forensic_platform.db")


@contextmanager
def get_connection():
    """Context manager that yields a SQLite connection with row factory set.
    UPGRADE 12: SQLite disables foreign-key enforcement by default per
    connection — explicitly enable it here so FK constraints declared in
    the schema are actually enforced."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Create all required tables if they do not already exist."""
    with get_connection() as conn:
        cur = conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT DEFAULT 'OPEN',
            overall_risk REAL DEFAULT 0,
            risk_level TEXT DEFAULT 'UNKNOWN'
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS email_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER NOT NULL,
            sender TEXT,
            receiver TEXT,
            subject TEXT,
            classification TEXT,
            risk_score REAL,
            indicators TEXT,
            timestamp TEXT,
            FOREIGN KEY (investigation_id) REFERENCES investigations (id)
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS network_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            classification TEXT,
            risk_score REAL,
            indicators TEXT,
            timestamp TEXT,
            FOREIGN KEY (investigation_id) REFERENCES investigations (id)
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS document_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER NOT NULL,
            document_name TEXT,
            document_type TEXT,
            ocr_text TEXT,
            authenticity_score REAL,
            identity_consistency_score REAL,
            risk_score REAL,
            indicators TEXT,
            timestamp TEXT,
            FOREIGN KEY (investigation_id) REFERENCES investigations (id)
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS geolocation_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER NOT NULL,
            ip_address TEXT,
            country TEXT,
            region TEXT,
            city TEXT,
            latitude REAL,
            longitude REAL,
            risk_score REAL,
            indicators TEXT,
            timestamp TEXT,
            FOREIGN KEY (investigation_id) REFERENCES investigations (id)
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER NOT NULL,
            evidence_type TEXT,
            description TEXT,
            risk_score REAL,
            timestamp TEXT,
            FOREIGN KEY (investigation_id) REFERENCES investigations (id)
        )
        """)

        conn.commit()


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Investigation CRUD
# ---------------------------------------------------------------------------

def create_investigation(case_name):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO investigations (case_name, created_at, status, overall_risk, risk_level) "
            "VALUES (?, ?, 'OPEN', 0, 'UNKNOWN')",
            (case_name, _now())
        )
        return cur.lastrowid


def list_investigations():
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM investigations ORDER BY id DESC")
        return [dict(r) for r in cur.fetchall()]


def get_investigation(investigation_id):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def update_investigation_risk(investigation_id, overall_risk, risk_level):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE investigations SET overall_risk = ?, risk_level = ? WHERE id = ?",
            (overall_risk, risk_level, investigation_id)
        )


def delete_investigation(investigation_id):
    with get_connection() as conn:
        cur = conn.cursor()
        for table in ["email_analysis", "network_analysis", "document_analysis",
                      "geolocation_analysis", "evidence", "investigations"]:
            col = "id" if table == "investigations" else "investigation_id"
            cur.execute(f"DELETE FROM {table} WHERE {col} = ?", (investigation_id,))


# ---------------------------------------------------------------------------
# Email analysis
# ---------------------------------------------------------------------------

def insert_email_analysis(investigation_id, sender, receiver, subject,
                           classification, risk_score, indicators):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO email_analysis (investigation_id, sender, receiver, subject, "
            "classification, risk_score, indicators, timestamp) VALUES (?,?,?,?,?,?,?,?)",
            (investigation_id, sender, receiver, subject, classification,
             risk_score, indicators, _now())
        )
        return cur.lastrowid


def get_email_analysis(investigation_id):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM email_analysis WHERE investigation_id = ? ORDER BY id DESC",
                    (investigation_id,))
        return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Network analysis
# ---------------------------------------------------------------------------

def insert_network_analysis(investigation_id, source_ip, destination_ip, protocol,
                             classification, risk_score, indicators):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO network_analysis (investigation_id, source_ip, destination_ip, protocol, "
            "classification, risk_score, indicators, timestamp) VALUES (?,?,?,?,?,?,?,?)",
            (investigation_id, source_ip, destination_ip, protocol, classification,
             risk_score, indicators, _now())
        )
        return cur.lastrowid


def get_network_analysis(investigation_id):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM network_analysis WHERE investigation_id = ? ORDER BY id DESC",
                    (investigation_id,))
        return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Document analysis
# ---------------------------------------------------------------------------

def insert_document_analysis(investigation_id, document_name, document_type, ocr_text,
                              authenticity_score, identity_consistency_score,
                              risk_score, indicators):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO document_analysis (investigation_id, document_name, document_type, "
            "ocr_text, authenticity_score, identity_consistency_score, risk_score, indicators, "
            "timestamp) VALUES (?,?,?,?,?,?,?,?,?)",
            (investigation_id, document_name, document_type, ocr_text, authenticity_score,
             identity_consistency_score, risk_score, indicators, _now())
        )
        return cur.lastrowid


def get_document_analysis(investigation_id):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM document_analysis WHERE investigation_id = ? ORDER BY id DESC",
                    (investigation_id,))
        return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Geolocation analysis
# ---------------------------------------------------------------------------

def insert_geolocation_analysis(investigation_id, ip_address, country, region, city,
                                 latitude, longitude, risk_score, indicators):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO geolocation_analysis (investigation_id, ip_address, country, region, "
            "city, latitude, longitude, risk_score, indicators, timestamp) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (investigation_id, ip_address, country, region, city, latitude, longitude,
             risk_score, indicators, _now())
        )
        return cur.lastrowid


def get_geolocation_analysis(investigation_id):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM geolocation_analysis WHERE investigation_id = ? ORDER BY id DESC",
                    (investigation_id,))
        return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Generic evidence
# ---------------------------------------------------------------------------

def insert_evidence(investigation_id, evidence_type, description, risk_score):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO evidence (investigation_id, evidence_type, description, risk_score, "
            "timestamp) VALUES (?,?,?,?,?)",
            (investigation_id, evidence_type, description, risk_score, _now())
        )
        return cur.lastrowid


def get_evidence(investigation_id):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM evidence WHERE investigation_id = ? ORDER BY id ASC",
                    (investigation_id,))
        return [dict(r) for r in cur.fetchall()]


def get_all_investigations_summary():
    """Return a summary list used by the Overview dashboard."""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM investigations ORDER BY id DESC")
        return [dict(r) for r in cur.fetchall()]
