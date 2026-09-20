"""SQLite database helpers for scan history."""

import sqlite3
from pathlib import Path


DATABASE_PATH = Path("instance") / "scans.db"


def get_connection():
    """Create and return a connection to the scan-history database."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    """Create the scan-history table if it does not already exist."""
    connection = get_connection()

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                final_url TEXT,
                scanned_at TEXT NOT NULL,
                http_status INTEGER,
                overall_risk TEXT,
                total_findings INTEGER NOT NULL DEFAULT 0,
                critical_count INTEGER NOT NULL DEFAULT 0,
                high_count INTEGER NOT NULL DEFAULT 0,
                medium_count INTEGER NOT NULL DEFAULT 0,
                low_count INTEGER NOT NULL DEFAULT 0,
                info_count INTEGER NOT NULL DEFAULT 0
            )
            """
        )

        connection.commit()
    finally:
        connection.close()


def save_scan_summary(
    target_url,
    final_url,
    scanned_at,
    http_status,
    risk_results,
):
    """Save a completed scan summary to the database."""
    summary = risk_results.get("summary", {})

    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            INSERT INTO scans (
                target_url,
                final_url,
                scanned_at,
                http_status,
                overall_risk,
                total_findings,
                critical_count,
                high_count,
                medium_count,
                low_count,
                info_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target_url,
                final_url,
                scanned_at,
                http_status,
                risk_results.get("overall_risk", "Not Available"),
                summary.get("total", 0),
                summary.get("critical", 0),
                summary.get("high", 0),
                summary.get("medium", 0),
                summary.get("low", 0),
                summary.get("info", 0),
            ),
        )

        connection.commit()
        return cursor.lastrowid
    finally:
        connection.close()


def get_scan_history():
    """Return previous scans with newest scans first."""
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                id,
                target_url,
                final_url,
                scanned_at,
                http_status,
                overall_risk,
                total_findings,
                critical_count,
                high_count,
                medium_count,
                low_count,
                info_count
            FROM scans
            ORDER BY id DESC
            """
        ).fetchall()

        return [dict(row) for row in rows]
    finally:
        connection.close()


def get_scan_by_id(scan_id):
    """Return one scan-history record by ID."""
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT
                id,
                target_url,
                final_url,
                scanned_at,
                http_status,
                overall_risk,
                total_findings,
                critical_count,
                high_count,
                medium_count,
                low_count,
                info_count
            FROM scans
            WHERE id = ?
            """,
            (scan_id,),
        ).fetchone()

        return dict(row) if row else None
    finally:
        connection.close()


def clear_scan_history():
    """Delete all scan-history records from the database."""
    connection = get_connection()

    try:
        connection.execute("DELETE FROM scans")
        connection.commit()
    finally:
        connection.close()