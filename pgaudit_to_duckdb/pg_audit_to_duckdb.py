"""
pg_audit_to_duckdb
- Ingests PostgreSQL csvlog files (with pg_audit) into DuckDB
- Skips the newest (active) file by default
- Full-file read each run; idempotent via ANTI JOIN + unique index
- Skips files whose (mtime, size) did not change
- Config & log live in the script directory
"""

import sys
import os
import glob
import logging
import configparser

# ---- Optional dependency hint (stderr only if missing) ----
try:
    import duckdb
except ImportError:
    sys.stderr.write("ERROR: 'duckdb' not installed. Try: pip install duckdb\n")
    sys.exit(1)

# =========================
# Defaults & constants
# =========================
APP_NAME = "pg_audit_to_duckdb"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOGGER = logging.getLogger(APP_NAME)

DEFAULT_CONFIG_PATH = os.path.join(SCRIPT_DIR, f"{APP_NAME}.conf")
DEFAULT_LOG_PATH = os.path.join(SCRIPT_DIR, f"{APP_NAME}.log")


CONF_DESCRIPTION = """
# db_path : DuckDB database file
# log_dir : directory with PostgreSQL CSV logs
# file_glob : filename pattern. If rotation appends suffixes (e.g. .1), use postgresql_*.csv*.
# skip_newest : -true- skips the currently written file (recommended).
# force_reprocess : deletes and re-ingests selected files (use sparingly).
# message_prefix : filter to pg_audit lines
# log_file : Where to write log file
# log_level : script’s own logging. DEBUG > INFO > WARNING > ERROR > CRITICAL. Former covers latter. If set to WARNING it will log WARNING, ERROR and CRITICAL
"""

DEFAULTS = {
    "db_path": "/path/to/pgsql_logs.duckdb",
    "log_dir": "/path/to/pgsql_logs", 
    "file_glob": "postgresql_*.csv*",
    "skip_newest": "true",
    "force_reprocess": "false",
    "message_prefix": "AUDIT:%", 
    "log_file": DEFAULT_LOG_PATH,
    "log_level": "INFO", 
}

# pg_audit CSV column mapping (DuckDB read_csv -> columns=)
PG_AUDIT_COLUMNS = {
    "log_time": "VARCHAR",
    "user_name": "VARCHAR",
    "database_name": "VARCHAR",
    "process_id": "INT",
    "client_addr": "VARCHAR",
    "session_id": "VARCHAR",
    "session_line_num": "INT",
    "command_tag": "VARCHAR",
    "session_start_time": "VARCHAR",
    "virtual_transaction_id": "VARCHAR",
    "transaction_id": "BIGINT",
    "error_severity": "VARCHAR",
    "sql_state_code": "VARCHAR",
    "message": "VARCHAR",
    "detail": "VARCHAR",
    "hint": "VARCHAR",
    "internal_query": "VARCHAR",
    "internal_query_pos": "INT",
    "context": "VARCHAR",
    "query": "VARCHAR",
    "query_pos": "INT",
    "location": "VARCHAR",
    "application_name": "VARCHAR",
    "backend_type": "VARCHAR",
    "leader_pid": "INT",
    "query_id": "BIGINT",
}

# =========================
# Utilities
# =========================
def configure_logging(log_file: str, level_name: str):
    """File logging. Relative paths are resolved against the script directory."""
    if not os.path.isabs(log_file):
        log_file = os.path.join(SCRIPT_DIR, log_file)
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    LOGGER.handlers.clear()
    LOGGER.setLevel(getattr(logging, level_name.upper(), logging.INFO))
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOGGER.addHandler(fh)
    LOGGER.propagate = False
    LOGGER.info("Logging initialized: file=%s level=%s", log_file, level_name.upper())


def boolify(val: str) -> bool:
    return str(val).strip().lower() in ("1", "true", "yes", "on")


def load_or_create_config() -> dict:
    """
    Create (if missing) and load the INI config in the script directory.
    Inline comments (#, ;) are supported; interpolation is disabled.
    """
    cfg_path = DEFAULT_CONFIG_PATH
    cfg = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#", ";"))

    created = False
    if not os.path.exists(cfg_path):
        cfg[APP_NAME] = DEFAULTS
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(
                f"# {APP_NAME} configuration\n"
                "# Auto-created on first run. Adjust values as needed.\n"
                "# Boolean values: true/false, yes/no, on/off, 1/0\n\n"
                f"{CONF_DESCRIPTION}\n\n"
            )
            cfg.write(f)
            f.flush()
            os.fsync(f.fileno())
        created = True

    cfg.read(cfg_path, encoding="utf-8")
    if APP_NAME not in cfg:
        cfg[APP_NAME] = DEFAULTS

    s = cfg[APP_NAME]
    vals = {
        "db_path": s.get("db_path", DEFAULTS["db_path"]),
        "log_dir": s.get("log_dir", DEFAULTS["log_dir"]),
        "file_glob": s.get("file_glob", DEFAULTS["file_glob"]),
        "skip_newest": boolify(s.get("skip_newest", DEFAULTS["skip_newest"])),
        "force_reprocess": boolify(s.get("force_reprocess", DEFAULTS["force_reprocess"])),
        "message_prefix": s.get("message_prefix", DEFAULTS["message_prefix"]),
        "log_file": s.get("log_file", DEFAULTS["log_file"]),
        "log_level": s.get("log_level", DEFAULTS["log_level"]),
        "config_path": cfg_path,
        "config_dir": SCRIPT_DIR,
    }
    if created:
        LOGGER.info("Created config at %s with defaults", cfg_path)
    return vals

# =========================
# DuckDB schema helpers
# =========================
def setup_database(db_path: str):
    """
    Ensure schema exists. Group-writable files via umask for shared setups.
    """
    os.umask(0o002)
    con = duckdb.connect(db_path)
    try:
        con.execute(
            """
            CREATE SEQUENCE IF NOT EXISTS log_path_id_seq;
            CREATE TABLE IF NOT EXISTS log_paths (
                id   INTEGER PRIMARY KEY NOT NULL DEFAULT nextval('log_path_id_seq'),
                path VARCHAR UNIQUE
            );
            """
        )

        # Minimal, purpose-built summary table for change detection
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS log_summary (
                log_path_id INTEGER,
                file_name   VARCHAR,
                last_mtime  DOUBLE,
                last_size   BIGINT,
                PRIMARY KEY (log_path_id, file_name),
                FOREIGN KEY (log_path_id) REFERENCES log_paths(id)
            );
            """
        )

        # Main audit table (columns we actually persist/query)
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                log_time        TIMESTAMP,
                user_name       VARCHAR,
                database_name   VARCHAR,
                client_addr     VARCHAR,
                message         VARCHAR,
                application_name VARCHAR,
                session_id      VARCHAR,
                session_line_num INT,
                log_path_id     INTEGER,
                file_name       VARCHAR,
                FOREIGN KEY (log_path_id) REFERENCES log_paths(id)
            );
            """
        )

        # Unique key to identify an audit row per source path
        con.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_unique
            ON audit_logs (log_path_id, session_id, session_line_num);
            """
        )
    finally:
        con.close()


def log_paths_insert_path(db_path: str, log_directory: str):
    """Register the directory in log_paths (idempotent)."""
    if not os.path.isdir(log_directory):
        LOGGER.error("Configured log_dir does not exist or is not accessible: %s", log_directory)
        sys.exit(1)
    normalized = log_directory.rstrip("/")
    con = duckdb.connect(db_path)
    try:
        con.execute(
            "INSERT INTO log_paths (path) VALUES (?) ON CONFLICT (path) DO NOTHING;", [normalized]
        )
        con.commit()
    finally:
        con.close()


def get_log_path_id(db_path: str, log_directory: str) -> int:
    """Resolve log_paths.id for the directory."""
    normalized = log_directory.rstrip("/")
    con = duckdb.connect(db_path)
    try:
        row = con.execute("SELECT id FROM log_paths WHERE path = ?;", [normalized]).fetchone()
        if not row:
            raise ValueError(f"Log path '{normalized}' not found in database.")
        return row[0]
    finally:
        con.close()


def get_summary_state(con, log_path_id: int, file_name: str):
    """Return (last_mtime, last_size) or (None, None)."""
    row = con.execute(
        """
        SELECT last_mtime, last_size FROM log_summary
        WHERE log_path_id = ? AND file_name = ?;
        """,
        [log_path_id, file_name],
    ).fetchone()
    return (row[0], row[1]) if row else (None, None)


def set_summary_state(con, log_path_id: int, file_name: str, mtime: float, size: int):
    """Upsert current mtime/size after processing."""
    con.execute(
        """
        INSERT OR REPLACE INTO log_summary
        (log_path_id, file_name, last_mtime, last_size)
        VALUES (?, ?, ?, ?);
        """,
        [log_path_id, file_name, mtime, size],
    )
    con.commit()

# =========================
# Processing
# =========================
def files_excluding_newest(files: list[str], skip_newest: bool) -> list[str]:
    """
    Sort by mtime and optionally drop the newest file.
    Why: the newest file is likely still being written by PostgreSQL.
    """
    try:
        files = sorted(files, key=lambda f: os.path.getmtime(f))
    except FileNotFoundError:
        files = [f for f in files if os.path.exists(f)]
        files = sorted(files, key=lambda f: os.path.getmtime(f))
    if skip_newest and files:
        return files[:-1]
    return files


def process_directory(
    db_path: str,
    log_dir: str,
    file_glob: str,
    message_prefix: str,
    force_reprocess: bool,
    skip_newest: bool,
):
    """Process all matching files in the directory (skipping the newest by default)."""
    log_path_id = get_log_path_id(db_path, log_dir)

    pattern = os.path.join(log_dir, file_glob)
    all_files = sorted(glob.glob(pattern))
    LOGGER.info("Found %d files in %s matching '%s'", len(all_files), log_dir, file_glob)

    files = files_excluding_newest(all_files, skip_newest)
    LOGGER.info("Selected %d file(s) (newest excluded: %s)", len(files), bool(skip_newest))
    if not files:
        LOGGER.warning("No eligible files to process.")
        return

    processed = 0
    for log_file in files:
        fname = os.path.basename(log_file)
        try:
            mtime = os.path.getmtime(log_file)
            fsize = os.path.getsize(log_file)
        except FileNotFoundError:
            LOGGER.warning("Skipped (file vanished): %s", fname)
            continue

        con = duckdb.connect(db_path)
        try:
            last_mtime, last_size = get_summary_state(con, log_path_id, fname)
            if not force_reprocess and last_mtime is not None and last_size is not None:
                if last_mtime == mtime and last_size == fsize:
                    LOGGER.info("Unchanged, skipping: %s", fname)
                    con.close()
                    continue

            if force_reprocess:
                LOGGER.warning("Force mode: deleting existing rows for %s", fname)
                con.execute(
                    "DELETE FROM audit_logs WHERE log_path_id = ? AND file_name = ?;",
                    [log_path_id, fname],
                )
                con.commit()

            # Full read; insert only rows not already present (dedup by ANTI JOIN)
            con.execute(
                """
                INSERT INTO audit_logs
                SELECT 
                    CASE 
                        WHEN log_time LIKE '%UTC%'
                            THEN strptime(log_time, '%Y-%m-%d %H:%M:%S.%f UTC')::TIMESTAMP
                        ELSE    strptime(log_time, '%Y-%m-%d %H:%M:%S.%f %z')::TIMESTAMP
                    END AS log_time,
                    user_name,
                    database_name,
                    client_addr,
                    message,
                    application_name,
                    session_id,
                    session_line_num,
                    ? AS log_path_id,
                    ? AS file_name
                FROM (
                    SELECT * FROM read_csv(?, 
                        columns=?, header=FALSE, delim=',', quote='"', escape='"',
                        nullstr='',
                        ignore_errors=TRUE,     -- tolerate malformed/multiline rows
                        null_padding=TRUE,      -- pad short rows
                        auto_detect=FALSE,
                        sample_size=-1          -- scan all to avoid mis-detection
                    )
                    WHERE TRIM(message) LIKE ?
                ) s
                ANTI JOIN audit_logs t
                  ON t.log_path_id      = ?
                 AND t.session_id       = s.session_id
                 AND t.session_line_num = s.session_line_num;
                """,
                [log_path_id, fname, log_file, PG_AUDIT_COLUMNS, message_prefix, log_path_id],
            )
            con.commit()

            set_summary_state(con, log_path_id, fname, mtime, fsize)
            LOGGER.info("Processed: %s (ingest idempotent; duplicates ignored)", fname)
            processed += 1
        except duckdb.Error as e:
            LOGGER.exception("DuckDB error on %s: %s", fname, e)
        finally:
            con.close()

    if processed == 0:
        LOGGER.warning("No files processed in this run.")
    else:
        LOGGER.info("Run complete. Files processed: %d", processed)


def process_single_file(db_path: str, csv_file: str, message_prefix: str, force: bool):
    """Process a single CSV file (useful for ad-hoc ingestion)."""
    if not os.path.isfile(csv_file):
        LOGGER.error("File not found: %s", csv_file)
        sys.exit(1)

    dir_path = os.path.dirname(os.path.abspath(csv_file)).rstrip("/")
    file_name = os.path.basename(csv_file)

    setup_database(db_path)
    log_paths_insert_path(db_path, dir_path)
    log_path_id = get_log_path_id(db_path, dir_path)

    con = duckdb.connect(db_path)
    try:
        if force:
            LOGGER.warning("Force: deleting existing rows for %s", file_name)
            con.execute(
                "DELETE FROM audit_logs WHERE log_path_id = ? AND file_name = ?;",
                [log_path_id, file_name],
            )
            con.commit()

        con.execute(
            """
            INSERT INTO audit_logs
            SELECT 
                CASE 
                    WHEN log_time LIKE '%UTC%'
                        THEN strptime(log_time, '%Y-%m-%d %H:%M:%S.%f UTC')::TIMESTAMP
                    ELSE    strptime(log_time, '%Y-%m-%d %H:%M:%S.%f %z')::TIMESTAMP
                END AS log_time,
                user_name,
                database_name,
                client_addr,
                message,
                application_name,
                session_id,
                session_line_num,
                ? AS log_path_id,
                ? AS file_name
            FROM (
                SELECT * FROM read_csv(?, 
                    columns=?, header=FALSE, delim=',', quote='"', escape='"',
                    nullstr='',
                    ignore_errors=TRUE,
                    null_padding=TRUE,
                    auto_detect=FALSE,
                    sample_size=-1
                )
                WHERE TRIM(message) LIKE ?
            ) s
            ANTI JOIN audit_logs t
              ON t.log_path_id      = ?
             AND t.session_id       = s.session_id
             AND t.session_line_num = s.session_line_num;
            """,
            [log_path_id, file_name, csv_file, PG_AUDIT_COLUMNS, message_prefix, log_path_id],
        )
        con.commit()

        LOGGER.info("File mode complete: %s (ingest idempotent; duplicates ignored)", file_name)
    except duckdb.Error as e:
        LOGGER.exception("DuckDB error in file mode (%s): %s", file_name, e)
        sys.exit(1)
    finally:
        con.close()

# =========================
# CLI
# =========================
def print_help():
    exe = os.path.basename(sys.argv[0])
    print(
        "Usage:\n"
        f"  {exe}                               # directory mode (uses config in script dir)\n"
        f"  {exe} --file /path/file.csv [--db /path.db] [--force]\n\n"
        "Notes:\n"
        f"  • Config path: {DEFAULT_CONFIG_PATH}\n"
        f"  • Runs once (cron-friendly). Logs to: {DEFAULT_LOG_PATH}\n"
    )


def main():
    # Help?
    if any(a in ("-h", "--help") for a in sys.argv[1:]):
        print_help()
        return

    # Initial logging (defaults into script dir)
    configure_logging(DEFAULT_LOG_PATH, DEFAULTS["log_level"])

    args = sys.argv[1:]
    file_path = None
    db_override = None
    force = False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--file" and i + 1 < len(args):
            file_path = args[i + 1]
            i += 1
        elif a == "--db" and i + 1 < len(args):
            db_override = args[i + 1]
            i += 1
        elif a == "--force":
            force = True
        else:
            LOGGER.error("Invalid argument: %s (use --help)", a)
            sys.exit(1)
        i += 1

    # Config (create/read in script dir)
    cfg = load_or_create_config()

    # Reconfigure logging to the configured target
    configure_logging(cfg["log_file"], cfg["log_level"])

    # Effective settings
    db_path = db_override if db_override else cfg["db_path"]
    if not os.path.isdir(cfg["log_dir"]):
        LOGGER.error("Configured log_dir does not exist or is not accessible: %s", cfg["log_dir"])
        LOGGER.error("Edit config here: %s", cfg["config_path"])
        sys.exit(1)

    LOGGER.info("Config file: %s", cfg["config_path"])
    LOGGER.info("Log dir    : %s", cfg["log_dir"])
    LOGGER.info("DB Path    : %s", db_path)
    LOGGER.info("Mode       : %s", "FILE" if file_path else "DIRECTORY")

    try:
        setup_database(db_path)
        if file_path:
            process_single_file(
                db_path=db_path,
                csv_file=file_path,
                message_prefix=cfg["message_prefix"],
                force=force,
            )
        else:
            log_paths_insert_path(db_path, cfg["log_dir"])
            process_directory(
                db_path=db_path,
                log_dir=cfg["log_dir"],
                file_glob=cfg["file_glob"],
                message_prefix=cfg["message_prefix"],
                force_reprocess=cfg["force_reprocess"],
                skip_newest=cfg["skip_newest"],
            )
    except Exception as e:
        LOGGER.exception("Fatal error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
