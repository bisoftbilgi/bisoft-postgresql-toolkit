# Advanced Password Policy Extension for PostgreSQL (`password_profile`)

`password_profile` is a PostgreSQL extension that enforces enterprise-level password policies by enhancing the default authentication mechanism with robust and configurable security checks. It is especially suitable for environments that require strong password hygiene, auditability, and compliance.

---

## 🔐 Features

- **Password Complexity Enforcement**: Enforces minimum length, uppercase, lowercase, digit, and special character rules.
- **Username Inclusion Prevention**: Blocks passwords containing the username.
- **Password History**: Prevents reuse of the last N passwords.
- **Reuse Interval Restriction**: Disallows reuse of recent passwords within a time window.
- **Password Expiration**: Forces password change after a configurable number of days, with optional grace period.
- **Failed Login Lockout**: Temporarily locks accounts after multiple failed login attempts.
- **Blacklist Validation**: Blocks weak or commonly used passwords via a user-managed blacklist table and file (`blacklist.txt`).
- **Custom Validation Hook**: Supports organization-specific password rules using pluggable SQL functions.
- **Fully Configurable via GUCs**: Every rule can be changed dynamically using PostgreSQL's configuration system (GUCs).

---

## 📦 Requirements

- **PostgreSQL** 16 or newer (`server`, `devel`, and `contrib` packages)
- **Rocky Linux (recommended)**:
  ```bash
  sudo dnf install postgresql16-server postgresql16-devel postgresql16-contrib
  sudo dnf groupinstall "Development Tools"
  ```

---

## ⚙️ Installation

### 1. Build the Extension

Create a `Makefile` in the extension root directory:

```make
MODULES = password_profile
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
```

Then compile and install:

```bash
make
sudo make install
```

---

### 2. PostgreSQL Configuration

Enable the extension in `postgresql.conf`:

```ini
shared_preload_libraries = 'password_profile'
```

Then restart the PostgreSQL server:

```bash
sudo systemctl restart postgresql-16
```

---

### 3. Initialize Schema and Tables

Connect to the target database as a superuser and run:

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS password_profile;

CREATE TABLE IF NOT EXISTS password_profile.history (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    change_date TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS password_profile.blacklist (
    word TEXT PRIMARY KEY
);

REVOKE ALL ON SCHEMA password_profile FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA password_profile FROM PUBLIC;
GRANT SELECT ON password_profile.blacklist TO PUBLIC;
```

---

## ⚙️ Configuration Parameters

All parameters can be adjusted via `postgresql.conf`, `ALTER SYSTEM`, or `SET` (where allowed). They are dynamically reloaded using `pg_reload_conf()`.

| Parameter                             | Description                                                                 | Default |
|--------------------------------------|-----------------------------------------------------------------------------|---------|
| `password_profile.min_length`        | Minimum password length                                                    | `8`     |
| `password_profile.require_upper`     | Requires at least one uppercase letter                                     | `true`  |
| `password_profile.require_lower`     | Requires at least one lowercase letter                                     | `true`  |
| `password_profile.require_digit`     | Requires at least one digit                                                | `true`  |
| `password_profile.require_special`   | Requires at least one special character                                    | `false` |
| `password_profile.expiration_days`   | Days before a password expires (0 to disable)                              | `0`     |
| `password_profile.grace_days`        | Days of grace period after expiration                                      | `0`     |
| `password_profile.reuse_time_days`   | Days before a password can be reused                                       | `0`     |
| `password_profile.reuse_max`         | Number of recent passwords disallowed for reuse                            | `3`     |
| `password_profile.enable_blacklist`  | Enables blacklist-based password rejection                                 | `true`  |
| `password_profile.failed_login_max`  | Number of failed logins before account is temporarily locked               | `10`    |
| `password_profile.lockout_time_mins` | Lockout duration in minutes                                                | `1440`  |
| `password_profile.allow_hashed`      | If true, hashed passwords bypass checks (e.g., MD5, SCRAM)                 | `false` |
| `password_profile.verify_function`   | Name of custom SQL function for additional password checks                 | `""`    |

#### Example:

```sql
ALTER SYSTEM SET password_profile.min_length = 12;
ALTER SYSTEM SET password_profile.failed_login_max = 5;
SELECT pg_reload_conf();
```

---

## 📄 Blacklist Management

Passwords in the blacklist are compared **case-insensitively** and **as substrings**, e.g., `Ahmet123` will match `ahmet`.

### Insert Manually:

```sql
INSERT INTO password_profile.blacklist (word)
VALUES ('123456'), ('password'), ('qwerty');
```

### Load from File (`blacklist.txt` with 10K entries)

If you have a `blacklist.txt` file (one password per line), you can bulk load it:

```bash
psql -U postgres -d yourdb -c "
    COPY password_profile.blacklist(word)
    FROM '/full/path/to/blacklist.txt'
    WITH (FORMAT text);
"
```

> ⚠️ Make sure the PostgreSQL server has read access to the file.

---

## ❌ Uninstallation

1. Remove from `postgresql.conf`:
   ```ini
   shared_preload_libraries = ''
   ```
2. Restart PostgreSQL:
   ```bash
   sudo systemctl restart postgresql-16
   ```
3. Drop schema and extension:
   ```sql
   DROP EXTENSION password_profile;
   DROP SCHEMA password_profile CASCADE;
   ```
4. Remove the `.so` and related files:
   ```bash
   sudo make uninstall
   ```

