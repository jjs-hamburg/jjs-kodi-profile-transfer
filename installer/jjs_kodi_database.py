#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kodi MusicDB / VideoDB backup format used by JJS Music Library Manager.

Format version 2 is intentionally kept compatible:
  manifest.json
  schema.json
  data/NNNN.sql

MariaDB backups use the same schema/data representation as the Library Manager.
SQLite backups use the same ZIP layout and manifest fields; database_charset.charset
is "sqlite3" so restores can safely reject cross-engine restores.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import tempfile
import xml.etree.ElementTree as ET
import zipfile

try:
    import pymysql
except ImportError:
    pymysql = None


BACKUP_FORMAT_VERSION = 2
DATA_BATCH_ROWS = 250
DATA_BATCH_MAX_CHARS = 512 * 1024
RESTORE_MERGE_MAX_CHARS = 8 * 1024 * 1024

MAGIC = {
    "music": "JJS_MUSIC_DB_BACKUP",
    "video": "JJS_VIDEO_DB_BACKUP",
}
PREFIX = {
    "music": "MyMusic",
    "video": "MyVideos",
}


def _progress(callback, value: float, text: str) -> None:
    if callback is not None:
        callback(float(value), str(text))


def _log(callback, text: str) -> None:
    if callback is not None:
        callback(str(text))


def _safe_ident(name: str) -> str:
    tick = chr(96)
    return tick + str(name).replace(tick, tick + tick) + tick


def _sqlite_ident(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _split_insert_rows(statement: str) -> tuple[str, list[str]] | None:
    """Split one generated multi-row INSERT into its row tuples.

    Used only as a recovery path after a bulk INSERT fails. The parser understands
    quoted SQL strings, doubled quotes and MariaDB-style backslash escapes.
    """
    text = str(statement or "").strip()
    match = re.match(r"(?is)^(INSERT\s+INTO\s+.+?\s+VALUES\s+)(.*?);?\s*$", text)
    if not match:
        return None
    prefix = match.group(1)
    body = match.group(2).strip()
    rows: list[str] = []
    start = None
    depth = 0
    quote = ""
    escaped = False
    i = 0
    while i < len(body):
        ch = body[i]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                if i + 1 < len(body) and body[i + 1] == quote:
                    i += 1
                else:
                    quote = ""
        else:
            if ch in ("'", '"'):
                quote = ch
            elif ch == "(":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    return None
                if depth == 0 and start is not None:
                    rows.append(body[start : i + 1])
                    start = None
            elif depth == 0 and ch not in (" ", "\t", "\r", "\n", ","):
                return None
        i += 1
    if quote or depth != 0 or start is not None or not rows:
        return None
    return prefix, rows


def _execute_insert_rows_resilient(execute, prefix: str, rows: list[str], table_name: str, log=None) -> int:
    """Execute rows in large batches; isolate only genuinely bad rows by binary splitting."""
    if not rows:
        return 0
    statement = prefix + ",".join(rows) + ";"
    try:
        execute(statement)
        return 0
    except Exception as bulk_error:
        if len(rows) == 1:
            preview = rows[0].replace("\r", " ").replace("\n", " ")
            if len(preview) > 180:
                preview = preview[:177] + "..."
            _log(
                log,
                f"WARNING: skipped bad row in {table_name}: {bulk_error} | {preview}",
            )
            return 1
        mid = len(rows) // 2
        return (
            _execute_insert_rows_resilient(execute, prefix, rows[:mid], table_name, log)
            + _execute_insert_rows_resilient(execute, prefix, rows[mid:], table_name, log)
        )


def _execute_insert_resilient(execute, statement: str, table_name: str, log=None) -> int:
    """Execute one generated INSERT with binary-split fallback on bad rows."""
    split = _split_insert_rows(statement)
    if split is None:
        execute(statement)
        return 0
    prefix, rows = split
    return _execute_insert_rows_resilient(execute, prefix, rows, table_name, log)


def _iter_merged_insert_statements(raw, max_chars: int = RESTORE_MERGE_MAX_CHARS):
    """Merge compatible backup INSERT lines into much larger restore statements."""
    pending_prefix = None
    pending_rows: list[str] = []
    pending_chars = 0

    def flush():
        nonlocal pending_prefix, pending_rows, pending_chars
        if not pending_rows or pending_prefix is None:
            return None
        statement = pending_prefix + ",".join(pending_rows) + ";"
        pending_prefix = None
        pending_rows = []
        pending_chars = 0
        return statement

    for raw_line in raw:
        line = raw_line.decode("utf-8").strip()
        if not line:
            continue
        split = _split_insert_rows(line)
        if split is None:
            statement = flush()
            if statement is not None:
                yield statement
            yield line
            continue

        prefix, rows = split
        rows_chars = sum(len(row) + 1 for row in rows)
        if (
            pending_rows
            and (
                prefix != pending_prefix
                or pending_chars + rows_chars > max_chars
            )
        ):
            statement = flush()
            if statement is not None:
                yield statement

        if pending_prefix is None:
            pending_prefix = prefix

        if rows_chars > max_chars and not pending_rows:
            yield prefix + ",".join(rows) + ";"
            pending_prefix = None
            pending_rows = []
            pending_chars = 0
            continue

        pending_rows.extend(rows)
        pending_chars += rows_chars

    statement = flush()
    if statement is not None:
        yield statement

def _safe_backup_part(value: str, fallback: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or fallback)).strip("._-")
    return text or fallback


def make_backup_name(db_name: str, source_id: str = "") -> str:
    stamp = dt.datetime.now().strftime("%y%m%d-%H%M")
    safe_db = _safe_backup_part(db_name, "KodiDB")
    if safe_db.lower().endswith(".db"):
        safe_db = safe_db[:-3]
    safe_source = _safe_backup_part(source_id, "unknown")
    return f"{safe_db}-{safe_source}-{stamp}.zip"


def _unique_backup_destination(destination_folder: Path, db_name: str, source_id: str) -> Path:
    folder = Path(destination_folder)
    candidate = folder / make_backup_name(db_name, source_id)
    if not candidate.exists():
        return candidate
    stem = candidate.stem
    suffix = candidate.suffix
    n = 2
    while True:
        numbered = folder / f"{stem}-{n}{suffix}"
        if not numbered.exists():
            return numbered
        n += 1


def parse_advancedsettings(xml_text: str, kind: str) -> dict | None:
    """Return MariaDB config for one Kodi DB kind, or None for local SQLite."""
    if kind not in MAGIC:
        raise ValueError(f"Unknown database kind: {kind}")
    raw = str(xml_text or "").lstrip("\ufeff").strip()
    if not raw:
        return None
    root = ET.fromstring(raw)
    tag = f"{kind}database"
    node = root.find(tag)
    if node is None:
        node = root.find(f".//{tag}")
    if node is None:
        return None

    def child(name, default=""):
        names = name if isinstance(name, tuple) else (name,)
        for item in names:
            found = node.find(item)
            if found is not None and found.text is not None:
                value = found.text.strip()
                if value:
                    return value
        return default

    host = child("host")
    user = child("user")
    db_type = child("type", "").lower()
    if not db_type and host and user:
        db_type = "mysql"
    if db_type not in ("mysql", "mariadb"):
        return None
    if not host or not user:
        raise RuntimeError(f"<{tag}> contains no host/user.")

    try:
        port = int(child("port", "3306"))
    except ValueError:
        port = 3306
    try:
        timeout = int(child("connecttimeout", "5"))
    except ValueError:
        timeout = 5

    return {
        "host": host,
        "port": port,
        "user": user,
        "password": child(("pass", "password"), ""),
        "prefix": child("name", PREFIX[kind]) or PREFIX[kind],
        "timeout": max(1, min(timeout, 30)),
        "ssl_ca": child("ca"),
        "ssl_cert": child("cert"),
        "ssl_key": child("key"),
    }


def backup_engine(manifest: dict) -> str:
    charset = str((manifest.get("database_charset") or {}).get("charset") or "").lower()
    return "sqlite" if charset == "sqlite3" else "mariadb"


def _connect_maria(cfg: dict, database: str | None = None, maintenance: bool = False):
    if pymysql is None:
        raise RuntimeError("PyMySQL is unavailable.")
    kwargs = {
        "host": cfg["host"],
        "port": int(cfg.get("port") or 3306),
        "user": cfg["user"],
        "password": cfg.get("password", ""),
        "charset": "utf8mb4",
        "connect_timeout": int(cfg.get("timeout") or 5),
        "read_timeout": 600 if maintenance else 15,
        "write_timeout": 600 if maintenance else 15,
        "autocommit": True,
    }
    if database:
        kwargs["database"] = database

    ssl = {}
    for key, out_key in (("ssl_ca", "ca"), ("ssl_cert", "cert"), ("ssl_key", "key")):
        value = str(cfg.get(key) or "").strip()
        if value:
            local = Path(value)
            if not local.is_file():
                raise RuntimeError(
                    f"MariaDB TLS file from advancedsettings.xml is not available on this PC: {value}"
                )
            ssl[out_key] = str(local)
    if ssl:
        kwargs["ssl"] = ssl
    return pymysql.connect(**kwargs)


def _schema_version_maria(con) -> int:
    with con.cursor() as cur:
        cur.execute("SELECT idVersion FROM version ORDER BY idVersion DESC LIMIT 1")
        row = cur.fetchone()
    if not row:
        raise RuntimeError("Kodi database contains no schema version.")
    return int(row[0])


def _schema_looks_like(cur, db_name: str, kind: str) -> bool:
    probes = ("song", "album") if kind == "music" else ("path", "version")
    try:
        for table in probes:
            cur.execute(
                f"SELECT COUNT(*) FROM {_safe_ident(db_name)}.{_safe_ident(table)} LIMIT 1"
            )
            cur.fetchone()
        return True
    except Exception:
        return False


def discover_mariadb(cfg: dict, kind: str) -> tuple[str, int]:
    prefix = str(cfg.get("prefix") or PREFIX[kind])
    con = _connect_maria(cfg)
    try:
        with con.cursor() as cur:
            show_error = None
            try:
                cur.execute("SHOW DATABASES")
                names = [str(row[0]) for row in cur.fetchall()]
            except Exception as exc:
                show_error = exc
                names = []

            pattern = re.compile(r"^{}(\d+)?$".format(re.escape(prefix)), re.IGNORECASE)
            candidates = [name for name in names if pattern.match(name)]
            if not candidates and _schema_looks_like(cur, prefix, kind):
                candidates = [prefix]
            if not candidates:
                detail = f"; SHOW DATABASES: {show_error}" if show_error else ""
                raise RuntimeError(f"No Kodi {kind} database with prefix {prefix} found{detail}")

            ranked = []
            for name in candidates:
                version = -1
                try:
                    cur.execute(
                        f"SELECT idVersion FROM {_safe_ident(name)}.version ORDER BY idVersion DESC LIMIT 1"
                    )
                    row = cur.fetchone()
                    if row:
                        version = int(row[0])
                except Exception:
                    pass
                suffix = -1
                match = re.search(r"(\d+)$", name)
                if match:
                    suffix = int(match.group(1))
                ranked.append((version, suffix, name))
            ranked.sort()
            version, _suffix, selected = ranked[-1]
            if version < 0:
                db_con = _connect_maria(cfg, selected)
                try:
                    version = _schema_version_maria(db_con)
                finally:
                    db_con.close()
            return selected, version
    finally:
        con.close()


def _restore_target_mariadb(cfg: dict, kind: str, backup_version: int) -> tuple[str, bool]:
    """Resolve a restore target even when the Kodi DB is missing or incomplete."""
    prefix = str(cfg.get("prefix") or PREFIX[kind]).strip() or PREFIX[kind]

    try:
        discovered_db, _discovered_version = discover_mariadb(cfg, kind)
    except Exception:
        discovered_db = ""

    if discovered_db:
        try:
            db_con = _connect_maria(cfg, discovered_db)
            try:
                current_version = _schema_version_maria(db_con)
            finally:
                db_con.close()
        except Exception:
            # Existing database is incomplete/corrupt (for example after an
            # interrupted restore). Treat it as a disaster-recovery target.
            discovered_db = ""
        else:
            if int(current_version) != int(backup_version):
                raise RuntimeError(
                    f"Backup schema {backup_version} does not match current schema {current_version}."
                )
            return discovered_db, False

    suffix = str(int(backup_version))
    target = prefix if prefix.casefold().endswith(suffix.casefold()) else prefix + suffix

    con = _connect_maria(cfg)
    try:
        with con.cursor() as cur:
            cur.execute(
                "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s",
                (target,),
            )
            exists = cur.fetchone() is not None
    finally:
        con.close()

    return target, not exists

def resolve_mariadb_restore_target(cfg: dict, kind: str, backup_version: int) -> dict:
    """Describe the MariaDB target for restore without requiring an intact Kodi schema."""
    db_name, needs_create = _restore_target_mariadb(cfg, kind, backup_version)
    return {
        "database": db_name,
        "schema_version": int(backup_version),
        "needs_create": bool(needs_create),
    }


def _database_charset(con, db_name: str) -> dict:
    with con.cursor() as cur:
        cur.execute(
            "SELECT DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME "
            "FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s",
            (db_name,),
        )
        row = cur.fetchone()
    return {
        "charset": str((row or ("utf8mb4", ""))[0] or "utf8mb4"),
        "collation": str((row or ("", ""))[1] or ""),
    }


def _show_create_item(con, statement: str, create_columns, name: str, **extra) -> dict:
    with con.cursor() as cur:
        cur.execute(statement)
        row = cur.fetchone()
        columns = [str(col[0]) for col in (cur.description or [])]
    if not row:
        raise RuntimeError(f"SHOW CREATE returned no result: {statement}")
    values = {columns[i].casefold(): row[i] for i in range(min(len(columns), len(row)))}
    create = ""
    for column in create_columns:
        value = values.get(str(column).casefold())
        if value:
            create = str(value)
            break
    if not create:
        raise RuntimeError(f"SHOW CREATE did not return SQL for {statement}")
    item = {"name": str(name), "create": create}
    item.update(extra)
    metadata = {
        "sql_mode": "sql_mode",
        "time_zone": "time_zone",
        "character_set_client": "character_set_client",
        "collation_connection": "collation_connection",
        "database_collation": "Database Collation",
    }
    for target, source in metadata.items():
        value = values.get(source.casefold())
        if value is not None and str(value) != "":
            item[target] = str(value)
    return item

def _maria_object_names(con, db_name: str):
    with con.cursor() as cur:
        cur.execute("SHOW FULL TABLES")
        rows = cur.fetchall()
    tables, views, sequences = [], [], []
    for row in rows:
        name = str(row[0])
        obj_type = str(row[1] or "").upper()
        if obj_type == "VIEW":
            views.append(name)
        elif obj_type == "SEQUENCE":
            sequences.append(name)
        else:
            tables.append(name)

    with con.cursor() as cur:
        cur.execute(
            "SELECT TRIGGER_NAME FROM information_schema.TRIGGERS "
            "WHERE TRIGGER_SCHEMA=%s ORDER BY TRIGGER_NAME",
            (db_name,),
        )
        triggers = [str(row[0]) for row in cur.fetchall()]
        cur.execute(
            "SELECT ROUTINE_NAME, ROUTINE_TYPE FROM information_schema.ROUTINES "
            "WHERE ROUTINE_SCHEMA=%s ORDER BY ROUTINE_TYPE, ROUTINE_NAME",
            (db_name,),
        )
        routines = [
            {"name": str(row[0]), "type": str(row[1] or "").upper()}
            for row in cur.fetchall()
        ]
        cur.execute(
            "SELECT EVENT_NAME FROM information_schema.EVENTS "
            "WHERE EVENT_SCHEMA=%s ORDER BY EVENT_NAME",
            (db_name,),
        )
        events = [str(row[0]) for row in cur.fetchall()]

    for values in (tables, views, sequences, triggers, events):
        values.sort(key=str.casefold)
    routines.sort(key=lambda item: (item["type"].casefold(), item["name"].casefold()))
    return tables, views, triggers, routines, events, sequences


def _maria_objects(con, db_name: str):
    tables, view_names, trigger_names, routine_names, event_names, sequence_names = _maria_object_names(
        con, db_name
    )
    views = [
        _show_create_item(con, f"SHOW CREATE VIEW {_safe_ident(name)}", ("Create View",), name)
        for name in view_names
    ]
    triggers = [
        _show_create_item(
            con,
            f"SHOW CREATE TRIGGER {_safe_ident(name)}",
            ("SQL Original Statement", "Create Trigger"),
            name,
        )
        for name in trigger_names
    ]
    routines = []
    for item in routine_names:
        obj_type = item["type"]
        routines.append(
            _show_create_item(
                con,
                f"SHOW CREATE {obj_type} {_safe_ident(item['name'])}",
                ("Create Procedure", "Create Function"),
                item["name"],
                type=obj_type,
            )
        )
    events = [
        _show_create_item(con, f"SHOW CREATE EVENT {_safe_ident(name)}", ("Create Event",), name)
        for name in event_names
    ]
    sequences = [
        _show_create_item(
            con,
            f"SHOW CREATE SEQUENCE {_safe_ident(name)}",
            ("Create Table", "Create Sequence"),
            name,
        )
        for name in sequence_names
    ]
    for item in sequences:
        with con.cursor() as cur:
            cur.execute(f"SELECT * FROM {_safe_ident(item['name'])}")
            row = cur.fetchone()
        if row is None:
            raise RuntimeError(f"Sequence {item['name']} contains no state row.")
        values = []
        for value in row:
            escaped = con.escape(value)
            if isinstance(escaped, bytes):
                escaped = escaped.decode("ascii", "backslashreplace")
            values.append(str(escaped))
        item["state_insert"] = (
            f"INSERT INTO {_safe_ident(item['name'])} VALUES ({','.join(values)});"
        )
    return tables, views, triggers, routines, events, sequences


def _maria_create_table(con, name: str) -> str:
    item = _show_create_item(
        con, f"SHOW CREATE TABLE {_safe_ident(name)}", ("Create Table",), name
    )
    return item["create"]


def _write_maria_table_data(con, table_name: str, path: Path) -> int:
    if pymysql is None:
        raise RuntimeError("PyMySQL is unavailable.")
    row_count = 0
    prefix = f"INSERT INTO {_safe_ident(table_name)} VALUES "
    cur = con.cursor(pymysql.cursors.SSCursor)
    try:
        cur.execute(f"SELECT * FROM {_safe_ident(table_name)}")
        with path.open("w", encoding="utf-8", newline="\n") as out:
            batch, chars = [], 0
            while True:
                rows = cur.fetchmany(DATA_BATCH_ROWS)
                if not rows:
                    break
                for row in rows:
                    values = []
                    for value in row:
                        escaped = con.escape(value)
                        if isinstance(escaped, bytes):
                            escaped = escaped.decode("ascii", "backslashreplace")
                        values.append(str(escaped))
                    row_sql = "(" + ",".join(values) + ")"
                    estimate = len(row_sql) + 1
                    if batch and (
                        len(batch) >= DATA_BATCH_ROWS or chars + estimate > DATA_BATCH_MAX_CHARS
                    ):
                        out.write(prefix + ",".join(batch) + ";\n")
                        batch, chars = [], 0
                    batch.append(row_sql)
                    chars += estimate
                    row_count += 1
            if batch:
                out.write(prefix + ",".join(batch) + ";\n")
    finally:
        cur.close()
    return row_count


def _write_zip(
    destination: Path,
    manifest: dict,
    schema: dict,
    data_files: list[tuple[Path, str]],
) -> None:
    schema_bytes = json.dumps(
        schema, ensure_ascii=False, indent=2, sort_keys=True
    ).encode("utf-8")
    manifest["schema_sha256"] = _sha256_bytes(schema_bytes)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
    ) as zf:
        zf.writestr("manifest.json", json.dumps(
            manifest, ensure_ascii=False, indent=2, sort_keys=True
        ).encode("utf-8"))
        zf.writestr("schema.json", schema_bytes)
        for local, archive_name in data_files:
            zf.write(local, archive_name)
    with zipfile.ZipFile(destination, "r") as zf:
        bad = zf.testzip()
        if bad:
            raise RuntimeError(f"ZIP verification failed: {bad}")


def backup_mariadb(
    kind: str,
    cfg: dict,
    destination_folder: Path,
    kodi_version: str = "",
    source_id: str = "",
    progress=None,
    log=None,
) -> dict:
    db_name, schema_version = discover_mariadb(cfg, kind)
    destination = _unique_backup_destination(destination_folder, db_name, source_id or cfg.get("host", ""))
    _progress(progress, 4, "Connecting to MariaDB")
    con = _connect_maria(cfg, db_name, maintenance=True)
    try:
        with con.cursor() as cur:
            cur.execute("SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            cur.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT")
        _progress(progress, 8, "Reading database structure")
        tables, views, triggers, routines, events, sequences = _maria_objects(con, db_name)
        charset_info = _database_charset(con, db_name)
        schema = {
            "tables": [],
            "views": views,
            "triggers": triggers,
            "routines": routines,
            "events": events,
            "sequences": sequences,
        }
        table_manifest = []
        with tempfile.TemporaryDirectory(prefix=f"jjs-{kind}db-backup-") as tmp:
            tmp_root = Path(tmp)
            data_dir = tmp_root / "data"
            data_dir.mkdir()
            data_files = []
            total = max(1, len(tables))
            for idx, table_name in enumerate(tables):
                pct = 10 + int((idx / total) * 72)
                _progress(progress, pct, f"Table: {table_name}")
                create_sql = _maria_create_table(con, table_name)
                data_file = f"data/{idx:04d}.sql"
                local_data = tmp_root / data_file
                rows = _write_maria_table_data(con, table_name, local_data)
                digest = _sha256_file(local_data)
                schema["tables"].append(
                    {"name": table_name, "create": create_sql, "data_file": data_file}
                )
                table_manifest.append(
                    {
                        "name": table_name,
                        "data_file": data_file,
                        "rows": rows,
                        "sha256": digest,
                    }
                )
                data_files.append((local_data, data_file))
                _log(log, f"{kind} table {table_name}: {rows} rows")

            manifest = {
                "magic": MAGIC[kind],
                "format_version": BACKUP_FORMAT_VERSION,
                "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "database_kind": kind,
                "source_database": db_name,
                "source_is_testdb": False,
                "schema_version": schema_version,
                "database_charset": charset_info,
                "kodi_version": kodi_version or "",
                "tables": table_manifest,
                "views": [item["name"] for item in views],
                "triggers": [item["name"] for item in triggers],
                "routines": [
                    {"name": item["name"], "type": item["type"]} for item in routines
                ],
                "events": [item["name"] for item in events],
                "sequences": [item["name"] for item in sequences],
            }
            _progress(progress, 87, "Compressing backup")
            _write_zip(destination, manifest, schema, data_files)
        _progress(progress, 100, "Backup complete")
        return {
            "path": destination,
            "engine": "MariaDB",
            "database": db_name,
            "schema_version": schema_version,
        }
    finally:
        try:
            con.rollback()
        except Exception:
            pass
        con.close()


def validate_backup(path: Path, kind: str) -> tuple[dict, dict]:
    path = Path(path)
    try:
        zf = zipfile.ZipFile(path, "r")
    except Exception as exc:
        raise RuntimeError(f"Backup ZIP cannot be opened: {exc}") from exc
    try:
        bad = zf.testzip()
        if bad:
            raise RuntimeError(f"ZIP is damaged: {bad}")
        names = set(zf.namelist())
        if "manifest.json" not in names or "schema.json" not in names:
            raise RuntimeError("Not a JJS database backup: manifest or schema is missing.")
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        if manifest.get("magic") != MAGIC[kind]:
            raise RuntimeError(f"This is not a JJS {kind} database backup.")
        if int(manifest.get("format_version") or 0) != BACKUP_FORMAT_VERSION:
            raise RuntimeError("Unsupported JJS database backup format.")
        schema_bytes = zf.read("schema.json")
        if _sha256_bytes(schema_bytes) != str(manifest.get("schema_sha256") or ""):
            raise RuntimeError("Schema checksum does not match.")
        schema = json.loads(schema_bytes.decode("utf-8"))
        for key in ("tables", "views", "triggers", "routines", "events", "sequences"):
            if key not in schema:
                raise RuntimeError(f"Backup schema is incomplete: {key} is missing.")
        manifest_tables = manifest.get("tables") or []
        schema_tables = schema.get("tables") or []
        if [x.get("name") for x in manifest_tables] != [
            x.get("name") for x in schema_tables
        ]:
            raise RuntimeError("Table list differs between manifest and schema.")
        for item in manifest_tables:
            data_file = str(item.get("data_file") or "")
            if not data_file or data_file not in names:
                raise RuntimeError(f"Table data missing: {item.get('name') or '?'}")
            digest = hashlib.sha256(zf.read(data_file)).hexdigest()
            if digest != str(item.get("sha256") or ""):
                raise RuntimeError(f"Checksum mismatch: {item.get('name') or data_file}")
        for key in ("views", "triggers", "events", "sequences"):
            expected = [str(x) for x in (manifest.get(key) or [])]
            actual = [str(x.get("name") or "") for x in (schema.get(key) or [])]
            if expected != actual:
                raise RuntimeError(f"{key} list differs between manifest and schema.")
        expected_routines = [
            (str(x.get("type") or "").upper(), str(x.get("name") or ""))
            for x in (manifest.get("routines") or [])
        ]
        actual_routines = [
            (str(x.get("type") or "").upper(), str(x.get("name") or ""))
            for x in (schema.get("routines") or [])
        ]
        if expected_routines != actual_routines:
            raise RuntimeError("Routine list differs between manifest and schema.")
        return manifest, schema
    finally:
        zf.close()


def _maria_drop_schema(con, db_name: str) -> None:
    tables, views, triggers, routines, events, sequences = _maria_object_names(con, db_name)
    with con.cursor() as cur:
        cur.execute("SET FOREIGN_KEY_CHECKS=0")
        for name in events:
            cur.execute(f"DROP EVENT IF EXISTS {_safe_ident(name)}")
        for name in triggers:
            cur.execute(f"DROP TRIGGER IF EXISTS {_safe_ident(name)}")
        for name in views:
            cur.execute(f"DROP VIEW IF EXISTS {_safe_ident(name)}")
        for item in routines:
            obj_type = str(item.get("type") or "").upper()
            if obj_type in ("PROCEDURE", "FUNCTION"):
                cur.execute(f"DROP {obj_type} IF EXISTS {_safe_ident(item.get('name') or '')}")
        for name in sequences:
            cur.execute(f"DROP SEQUENCE IF EXISTS {_safe_ident(name)}")
        for name in tables:
            cur.execute(f"DROP TABLE IF EXISTS {_safe_ident(name)}")


def _maria_session_defaults(con) -> dict:
    with con.cursor() as cur:
        cur.execute(
            "SELECT @@SESSION.sql_mode, @@SESSION.time_zone, "
            "@@character_set_client, @@collation_connection"
        )
        row = cur.fetchone() or ("", "SYSTEM", "utf8mb4", "")
    return {
        "sql_mode": str(row[0] or ""),
        "time_zone": str(row[1] or "SYSTEM"),
        "character_set_client": str(row[2] or "utf8mb4"),
        "collation_connection": str(row[3] or ""),
    }


def _safe_charset(value, fallback):
    text = str(value or "").strip()
    return text if re.fullmatch(r"[A-Za-z0-9_]+", text) else fallback


def _maria_apply_session(cur, item: dict, defaults: dict) -> None:
    sql_mode = str(item.get("sql_mode", defaults["sql_mode"]))
    time_zone = str(item.get("time_zone", defaults["time_zone"]))
    charset = _safe_charset(
        item.get("character_set_client"),
        _safe_charset(defaults["character_set_client"], "utf8mb4"),
    )
    collation = _safe_charset(
        item.get("collation_connection"),
        _safe_charset(defaults["collation_connection"], ""),
    )
    cur.execute("SET SESSION sql_mode=%s", (sql_mode,))
    cur.execute("SET SESSION time_zone=%s", (time_zone,))
    if collation:
        cur.execute(f"SET NAMES {charset} COLLATE {collation}")
    else:
        cur.execute(f"SET NAMES {charset}")


def _maria_create_with_retries(con, items: list[dict], object_kind: str) -> None:
    pending = list(items)
    errors = {}
    defaults = _maria_session_defaults(con)
    try:
        for _pass in range(max(1, len(pending) + 1)):
            if not pending:
                return
            next_pending, made_progress = [], False
            for item in pending:
                key = f"{item.get('type') or object_kind}:{item.get('name') or '?'}"
                try:
                    with con.cursor() as cur:
                        _maria_apply_session(cur, item, defaults)
                        cur.execute(str(item.get("create") or ""))
                    made_progress = True
                    errors.pop(key, None)
                except Exception as exc:
                    next_pending.append(item)
                    errors[key] = str(exc)
            pending = next_pending
            if not made_progress:
                break
        if pending:
            first = pending[0]
            key = f"{first.get('type') or object_kind}:{first.get('name') or '?'}"
            raise RuntimeError(
                f"{object_kind} could not be created: {first.get('name') or '?'} – "
                f"{errors.get(key, 'unknown error')}"
            )
    finally:
        try:
            with con.cursor() as cur:
                _maria_apply_session(cur, {}, defaults)
        except Exception:
            pass


def _maria_rebase_sql(sql: str, source_db: str, target_db: str) -> str:
    text = str(sql or "")
    if not source_db or not target_db or source_db.casefold() == target_db.casefold():
        return text
    tick = chr(96)
    source_quoted = tick + source_db.replace(tick, tick + tick) + tick + "."
    target_quoted = tick + target_db.replace(tick, tick + tick) + tick + "."
    text = re.sub(re.escape(source_quoted), target_quoted, text, flags=re.IGNORECASE)
    if re.search(r"(?i)(?<![A-Za-z0-9_$\x60])" + re.escape(source_db) + r"\.", text):
        raise RuntimeError(
            f"Restore refused: object definition contains an unsafe reference to {source_db}."
        )
    return text


def _maria_schema_for_target(schema: dict, source_db: str, target_db: str) -> dict:
    cloned = json.loads(json.dumps(schema, ensure_ascii=False))
    for key in ("tables", "sequences", "routines", "views", "triggers", "events"):
        for item in cloned.get(key) or []:
            item["create"] = _maria_rebase_sql(item.get("create") or "", source_db, target_db)
    return cloned


def _apply_maria_charset(con, db_name: str, info: dict) -> None:
    charset = _safe_charset(info.get("charset"), "utf8mb4")
    collation = _safe_charset(info.get("collation"), "")
    with con.cursor() as cur:
        if collation:
            cur.execute(
                f"ALTER DATABASE {_safe_ident(db_name)} CHARACTER SET {charset} COLLATE {collation}"
            )
        else:
            cur.execute(f"ALTER DATABASE {_safe_ident(db_name)} CHARACTER SET {charset}")


def _restore_maria_data(con, zf: zipfile.ZipFile, table_item: dict, log=None) -> int:
    """Restore one MariaDB table in one transaction using large merged INSERTs."""
    data_file = str(table_item.get("data_file") or "")
    table_name = str(table_item.get("name") or data_file or "?")
    skipped = 0
    try:
        with con.cursor() as cur:
            cur.execute("SET SESSION FOREIGN_KEY_CHECKS=0")
            cur.execute("SET SESSION UNIQUE_CHECKS=0")
        con.begin()
        with zf.open(data_file, "r") as raw:
            for statement in _iter_merged_insert_statements(raw):
                def execute(sql: str) -> None:
                    with con.cursor() as cur:
                        cur.execute(sql)
                skipped += _execute_insert_resilient(execute, statement, table_name, log)
        con.commit()
        return skipped
    except Exception:
        try:
            con.rollback()
        except Exception:
            pass
        raise


def _verify_maria(
    con,
    manifest: dict,
    schema: dict,
    skipped_by_table: dict[str, int] | None = None,
) -> dict:
    expected_version = int(manifest.get("schema_version") or -1)
    actual_version = _schema_version_maria(con)
    if actual_version != expected_version:
        raise RuntimeError(
            f"Schema version after restore is {actual_version}, expected {expected_version}."
        )
    skipped_by_table = skipped_by_table or {}
    for item in manifest.get("tables") or []:
        name = str(item.get("name") or "")
        original_expected = int(item.get("rows") or 0)
        skipped = int(skipped_by_table.get(name, 0))
        expected = original_expected - skipped
        with con.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM {_safe_ident(name)}")
            actual = int((cur.fetchone() or (0,))[0] or 0)
        if actual != expected:
            raise RuntimeError(
                f"Table {name}: {actual} rows after restore, expected {expected} "
                f"({skipped} skipped from {original_expected})."
            )
    with con.cursor() as cur:
        cur.execute("SELECT DATABASE()")
        row = cur.fetchone()
    db_name = str((row or ("",))[0] or "")
    tables, views, triggers, routines, events, sequences = _maria_object_names(con, db_name)
    expected = {
        "tables": sorted(str(x.get("name") or "") for x in schema.get("tables") or []),
        "views": sorted(str(x.get("name") or "") for x in schema.get("views") or []),
        "triggers": sorted(str(x.get("name") or "") for x in schema.get("triggers") or []),
        "events": sorted(str(x.get("name") or "") for x in schema.get("events") or []),
        "sequences": sorted(str(x.get("name") or "") for x in schema.get("sequences") or []),
    }
    actual = {
        "tables": sorted(tables),
        "views": sorted(views),
        "triggers": sorted(triggers),
        "events": sorted(events),
        "sequences": sorted(sequences),
    }
    for key in expected:
        if actual[key] != expected[key]:
            raise RuntimeError(f"Restore verification failed for {key}.")
    expected_routines = sorted(
        (str(x.get("type") or "").upper(), str(x.get("name") or ""))
        for x in schema.get("routines") or []
    )
    actual_routines = sorted(
        (str(x.get("type") or "").upper(), str(x.get("name") or "")) for x in routines
    )
    if actual_routines != expected_routines:
        raise RuntimeError("Restore verification failed for routines.")
    return {
        "tables": len(expected["tables"]),
        "views": len(expected["views"]),
        "triggers": len(expected["triggers"]),
        "routines": len(expected_routines),
        "events": len(expected["events"]),
        "sequences": len(expected["sequences"]),
    }


def restore_mariadb(
    kind: str,
    cfg: dict,
    backup_path: Path,
    progress=None,
    log=None,
) -> dict:
    manifest, schema = validate_backup(backup_path, kind)
    if backup_engine(manifest) != "mariadb":
        raise RuntimeError("SQLite backup cannot be restored into MariaDB.")
    backup_version = int(manifest.get("schema_version") or -1)
    db_name, needs_create = _restore_target_mariadb(cfg, kind, backup_version)
    if needs_create:
        _progress(progress, 2, f"Creating MariaDB database {db_name}")
        _ensure_maria_database(cfg, db_name, manifest.get("database_charset") or {})
        _log(log, f"Created missing MariaDB database {db_name} from backup metadata.")
    source_db = str(manifest.get("source_database") or "")
    restore_schema = _maria_schema_for_target(schema, source_db, db_name)
    _progress(progress, 3, "Connecting to MariaDB")
    con = _connect_maria(cfg, db_name, maintenance=True)
    try:
        with zipfile.ZipFile(backup_path, "r") as zf:
            _progress(progress, 5, "Restoring database charset")
            _apply_maria_charset(con, db_name, manifest.get("database_charset") or {})
            _progress(progress, 7, "Removing existing schema")
            _maria_drop_schema(con, db_name)

            tables = restore_schema.get("tables") or []
            sequences = restore_schema.get("sequences") or []
            routines = restore_schema.get("routines") or []
            views = restore_schema.get("views") or []
            triggers = restore_schema.get("triggers") or []
            events = restore_schema.get("events") or []

            _maria_create_with_retries(con, sequences, "Sequence")
            for item in sequences:
                statement = str(item.get("state_insert") or "").strip()
                if statement:
                    with con.cursor() as cur:
                        cur.execute(statement)

            _progress(progress, 10, "Restoring table structure")
            _maria_create_with_retries(con, tables, "Table")
            skipped_by_table: dict[str, int] = {}
            total = max(1, len(tables))
            for idx, item in enumerate(tables):
                table_name = str(item.get("name") or "?")
                _progress(progress, 12 + int((idx / total) * 66), f"Data: {table_name}")
                skipped = _restore_maria_data(con, zf, item, log)
                if skipped:
                    skipped_by_table[table_name] = skipped

            _progress(progress, 80, "Restoring routines")
            _maria_create_with_retries(con, routines, "Routine")
            _progress(progress, 84, "Restoring views")
            _maria_create_with_retries(con, views, "View")
            _progress(progress, 88, "Restoring triggers")
            _maria_create_with_retries(con, triggers, "Trigger")
            _progress(progress, 90, "Restoring events")
            _maria_create_with_retries(con, events, "Event")

        with con.cursor() as cur:
            cur.execute("SET FOREIGN_KEY_CHECKS=1")
            cur.execute("SET UNIQUE_CHECKS=1")
        _progress(progress, 94, "Verifying restore")
        summary = _verify_maria(con, manifest, restore_schema, skipped_by_table)
        skipped_rows = sum(skipped_by_table.values())
        summary["skipped_rows"] = skipped_rows
        if skipped_rows:
            _log(log, f"WARNING: MariaDB restore completed with {skipped_rows} skipped row(s).")
        _progress(progress, 100, "Restore complete")
        _log(log, f"MariaDB restore verified: {summary}")
        return {
            "engine": "MariaDB",
            "database": db_name,
            "schema_version": backup_version,
            **summary,
        }
    except Exception:
        try:
            with con.cursor() as cur:
                cur.execute("SET FOREIGN_KEY_CHECKS=1")
        except Exception:
            pass
        raise
    finally:
        con.close()


def discover_sqlite_filename(filenames: list[str], kind: str) -> str:
    prefix = PREFIX[kind]
    pattern = re.compile(r"^{}(\d+)\.db$".format(re.escape(prefix)), re.IGNORECASE)
    ranked = []
    for name in filenames:
        match = pattern.match(Path(str(name)).name)
        if match:
            ranked.append((int(match.group(1)), Path(str(name)).name))
    if not ranked:
        raise RuntimeError(f"No local Kodi {kind} SQLite database ({prefix}*.db) found.")
    ranked.sort()
    return ranked[-1][1]


def _sqlite_schema_version(con: sqlite3.Connection) -> int:
    row = con.execute("SELECT idVersion FROM version ORDER BY idVersion DESC LIMIT 1").fetchone()
    if not row:
        raise RuntimeError("Kodi SQLite database contains no schema version.")
    return int(row[0])


def inspect_sqlite(path: Path, kind: str) -> dict:
    con = sqlite3.connect(str(path))
    try:
        version = _sqlite_schema_version(con)
        integrity = con.execute("PRAGMA integrity_check").fetchone()
        if not integrity or str(integrity[0]).lower() != "ok":
            raise RuntimeError(f"SQLite integrity check failed: {integrity}")
        probes = ("song", "album") if kind == "music" else ("path", "version")
        names = {str(row[0]) for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        for name in probes:
            if name not in names:
                raise RuntimeError(f"SQLite file does not look like Kodi {kind} DB: {name} missing.")
        return {"schema_version": version}
    finally:
        con.close()


def _sqlite_literal(value) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bytes):
        return "X'" + value.hex() + "'"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return "NULL"
        return repr(value)
    text = str(value).replace("'", "''")
    return "'" + text + "'"


def _write_sqlite_table_data(con: sqlite3.Connection, table_name: str, path: Path) -> int:
    row_count = 0
    prefix = f"INSERT INTO {_sqlite_ident(table_name)} VALUES "
    cur = con.execute(f"SELECT * FROM {_sqlite_ident(table_name)}")
    with path.open("w", encoding="utf-8", newline="\n") as out:
        batch, chars = [], 0
        while True:
            rows = cur.fetchmany(DATA_BATCH_ROWS)
            if not rows:
                break
            for row in rows:
                row_sql = "(" + ",".join(_sqlite_literal(v) for v in row) + ")"
                estimate = len(row_sql) + 1
                if batch and (len(batch) >= DATA_BATCH_ROWS or chars + estimate > DATA_BATCH_MAX_CHARS):
                    out.write(prefix + ",".join(batch) + ";\n")
                    batch, chars = [], 0
                batch.append(row_sql)
                chars += estimate
                row_count += 1
        if batch:
            out.write(prefix + ",".join(batch) + ";\n")
    return row_count


def backup_sqlite(
    kind: str,
    sqlite_path: Path,
    source_database: str,
    destination_folder: Path,
    kodi_version: str = "",
    source_id: str = "",
    progress=None,
    log=None,
) -> dict:
    sqlite_path = Path(sqlite_path)
    source_name = Path(source_database).stem
    destination = _unique_backup_destination(destination_folder, source_name, source_id)
    _progress(progress, 4, "Opening SQLite database")
    con = sqlite3.connect(str(sqlite_path))
    try:
        version = _sqlite_schema_version(con)
        integrity = con.execute("PRAGMA integrity_check").fetchone()
        if not integrity or str(integrity[0]).lower() != "ok":
            raise RuntimeError(f"SQLite integrity check failed: {integrity}")
        rows = con.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE sql IS NOT NULL ORDER BY type, name"
        ).fetchall()
        tables = []
        views = []
        triggers = []
        indexes_by_table: dict[str, list[str]] = {}
        for obj_type, name, table_name, sql in rows:
            obj_type = str(obj_type)
            name = str(name)
            if name.startswith("sqlite_"):
                continue
            if obj_type == "table":
                tables.append((name, str(sql)))
            elif obj_type == "view":
                views.append({"name": name, "create": str(sql)})
            elif obj_type == "trigger":
                triggers.append({"name": name, "create": str(sql)})
            elif obj_type == "index":
                indexes_by_table.setdefault(str(table_name), []).append(str(sql))

        tables.sort(key=lambda item: item[0].casefold())
        views.sort(key=lambda item: item["name"].casefold())
        triggers.sort(key=lambda item: item["name"].casefold())
        for values in indexes_by_table.values():
            values.sort(key=str.casefold)

        sequences = []
        try:
            sequence_rows = con.execute("SELECT name, seq FROM sqlite_sequence ORDER BY name").fetchall()
            if sequence_rows:
                statements = ["DELETE FROM sqlite_sequence;"]
                for name, seq in sequence_rows:
                    statements.append(
                        "INSERT INTO sqlite_sequence(name,seq) VALUES ({},{});".format(
                            _sqlite_literal(name), _sqlite_literal(seq)
                        )
                    )
                sequences.append({"name": "sqlite_sequence", "create": "", "state_insert": "\n".join(statements)})
        except sqlite3.OperationalError:
            pass

        schema = {
            "tables": [],
            "views": views,
            "triggers": triggers,
            "routines": [],
            "events": [],
            "sequences": sequences,
        }
        table_manifest = []
        with tempfile.TemporaryDirectory(prefix=f"jjs-{kind}db-sqlite-") as tmp:
            tmp_root = Path(tmp)
            data_dir = tmp_root / "data"
            data_dir.mkdir()
            data_files = []
            total = max(1, len(tables))
            for idx, (table_name, create_sql) in enumerate(tables):
                _progress(progress, 10 + int((idx / total) * 72), f"Table: {table_name}")
                index_sql = indexes_by_table.get(table_name) or []
                combined_create = create_sql.rstrip().rstrip(";") + ";"
                if index_sql:
                    combined_create += "\n" + "\n".join(item.rstrip().rstrip(";") + ";" for item in index_sql)
                data_file = f"data/{idx:04d}.sql"
                local_data = tmp_root / data_file
                row_count = _write_sqlite_table_data(con, table_name, local_data)
                digest = _sha256_file(local_data)
                schema["tables"].append({"name": table_name, "create": combined_create, "data_file": data_file})
                table_manifest.append({"name": table_name, "data_file": data_file, "rows": row_count, "sha256": digest})
                data_files.append((local_data, data_file))
                _log(log, f"{kind} table {table_name}: {row_count} rows")

            manifest = {
                "magic": MAGIC[kind],
                "format_version": BACKUP_FORMAT_VERSION,
                "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "database_kind": kind,
                "source_database": source_name,
                "source_is_testdb": False,
                "schema_version": version,
                "database_charset": {"charset": "sqlite3", "collation": ""},
                "kodi_version": kodi_version or "",
                "tables": table_manifest,
                "views": [item["name"] for item in views],
                "triggers": [item["name"] for item in triggers],
                "routines": [],
                "events": [],
                "sequences": [item["name"] for item in sequences],
            }
            _progress(progress, 88, "Compressing backup")
            _write_zip(destination, manifest, schema, data_files)

        _progress(progress, 100, "Backup complete")
        return {"path": destination, "engine": "SQLite", "database": source_name, "schema_version": version}
    finally:
        con.close()


def restore_sqlite(
    kind: str,
    backup_path: Path,
    current_db_path: Path,
    output_path: Path,
    progress=None,
    log=None,
) -> dict:
    manifest, schema = validate_backup(backup_path, kind)
    if backup_engine(manifest) != "sqlite":
        raise RuntimeError("MariaDB backup cannot be restored into SQLite.")
    current_info = inspect_sqlite(current_db_path, kind)
    current_version = int(current_info["schema_version"])
    backup_version = int(manifest.get("schema_version") or -1)
    if backup_version != current_version:
        raise RuntimeError(f"Backup schema {backup_version} does not match current schema {current_version}.")

    output_path = Path(output_path)
    output_path.unlink(missing_ok=True)
    _progress(progress, 5, "Creating SQLite database")
    con = sqlite3.connect(str(output_path))
    try:
        con.execute("PRAGMA foreign_keys=OFF")
        con.execute("PRAGMA journal_mode=DELETE")
        tables = schema.get("tables") or []
        with zipfile.ZipFile(backup_path, "r") as zf:
            _progress(progress, 8, "Restoring table structure")
            for item in tables:
                con.executescript(str(item.get("create") or ""))
            con.commit()

            skipped_by_table: dict[str, int] = {}
            total = max(1, len(tables))
            for idx, item in enumerate(tables):
                table_name = str(item.get("name") or "?")
                _progress(progress, 12 + int((idx / total) * 66), f"Data: {table_name}")
                data_file = str(item.get("data_file") or "")
                pending = ""
                skipped = 0
                with zf.open(data_file, "r") as raw:
                    for raw_line in raw:
                        pending += raw_line.decode("utf-8")
                        if sqlite3.complete_statement(pending):
                            statement = pending.strip()
                            if statement:
                                skipped += _execute_insert_resilient(
                                    con.execute, statement, table_name, log
                                )
                            pending = ""
                if pending.strip():
                    raise RuntimeError(
                        f"Incomplete SQL statement in backup table data: {table_name}"
                    )
                if skipped:
                    skipped_by_table[table_name] = skipped
                con.commit()

        _progress(progress, 80, "Restoring views")
        for item in schema.get("views") or []:
            con.executescript(str(item.get("create") or ""))
        _progress(progress, 86, "Restoring triggers")
        for item in schema.get("triggers") or []:
            con.executescript(str(item.get("create") or ""))
        for item in schema.get("sequences") or []:
            statement = str(item.get("state_insert") or "").strip()
            if statement:
                con.executescript(statement)
        con.commit()

        _progress(progress, 92, "Verifying restore")
        actual_version = _sqlite_schema_version(con)
        if actual_version != backup_version:
            raise RuntimeError(f"Schema version after restore is {actual_version}, expected {backup_version}.")
        for item in manifest.get("tables") or []:
            name = str(item.get("name") or "")
            original_expected = int(item.get("rows") or 0)
            skipped = int(skipped_by_table.get(name, 0))
            expected = original_expected - skipped
            actual = int(con.execute(f"SELECT COUNT(*) FROM {_sqlite_ident(name)}").fetchone()[0])
            if actual != expected:
                raise RuntimeError(
                    f"Table {name}: {actual} rows after restore, expected {expected} "
                    f"({skipped} skipped from {original_expected})."
                )
        integrity = con.execute("PRAGMA integrity_check").fetchone()
        if not integrity or str(integrity[0]).lower() != "ok":
            raise RuntimeError(f"SQLite integrity check failed after restore: {integrity}")
        skipped_rows = sum(skipped_by_table.values())
        if skipped_rows:
            _log(log, f"WARNING: SQLite restore completed with {skipped_rows} skipped row(s).")
        _progress(progress, 100, "Restore complete")
        _log(log, f"SQLite restore verified: {len(tables)} tables")
        return {
            "engine": "SQLite",
            "database": str(manifest.get("source_database") or ""),
            "schema_version": backup_version,
            "tables": len(tables),
            "skipped_rows": skipped_rows,
        }
    except Exception:
        try:
            con.close()
        finally:
            output_path.unlink(missing_ok=True)
        raise
    finally:
        try:
            con.close()
        except Exception:
            pass
