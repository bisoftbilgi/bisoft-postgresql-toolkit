
# Advanced Password Policy Extension for PostgreSQL (`password_profile`)

This PostgreSQL extension provides enterprise-grade password security by enforcing customizable and robust password policies. It significantly enhances the default authentication mechanism, helping administrators comply with strict security standards.

---

## 🔐 Features

- **Password Complexity**: Enforces rules for minimum length, uppercase/lowercase letters, digits, and special characters.
- **Username Restriction**: Prevents passwords from containing the username.
- **Password History**: Disallows reuse of the last N passwords.
- **Password Reuse Interval**: Prevents reusing passwords within a configurable number of days.
- **Password Expiration**: Forces users to change their passwords periodically with an optional grace period.
- **Failed Login Lockout**: Temporarily locks accounts after repeated failed login attempts.
- **Password Blacklist**: Blocks common or weak passwords via a blacklist table.
- **Custom Validation Function**: Supports organization-specific rules via user-defined SQL functions.
- **Fully Configurable via GUCs**: All rules are dynamically configurable using PostgreSQL's GUC system.

---

## Requirements

* **PostgreSQL:** Version 16 or newer, including the server, development, and contrib packages.
    * On **Rocky Linux**, you can install all necessary packages with a single command:
        ```bash
        sudo dnf install postgresql16-server postgresql16-devel postgresql16-contrib
        ```
* **C Compiler and Build Tools:** A standard C compiler like `gcc` and `make`.
    * On **Rocky Linux**, you can install these with:
        ```bash
        sudo dnf groupinstall "Development Tools"
        ```

### Installation on Rocky Linux

```bash
sudo dnf install postgresql16-server postgresql16-devel
sudo dnf groupinstall "Development Tools"
```

---

## ⚙️ Installation and Setup

### 1. Compilation

Create a `Makefile` in the same directory as `password_profile.c`:

```make
# Makefile for password_profile extension

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

Edit `postgresql.conf`:

```ini
# postgresql.conf
shared_preload_libraries = 'password_profile'
```

Then restart PostgreSQL:

```bash
sudo systemctl restart postgresql-16
```

---

### 3. Database Setup

Connect to your database as a superuser and execute:

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA password_profile;

CREATE TABLE password_profile.history (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    change_date TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE password_profile.blacklist (
    id SERIAL PRIMARY KEY,
    word TEXT NOT NULL UNIQUE
);

REVOKE ALL ON SCHEMA password_profile FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA password_profile FROM PUBLIC;
```

---

## ⚙️ Configuration Parameters

You can configure the policy using `postgresql.conf` or `ALTER SYSTEM`.

| Parameter                          | Description                                                                 | Default |
|-----------------------------------|-----------------------------------------------------------------------------|---------|
| `password_profile.min_length`       | Minimum password length                                                    | `8`     |
| `password_profile.require_upper`    | Requires at least one uppercase letter                                     | `true`  |
| `password_profile.require_lower`    | Requires at least one lowercase letter                                     | `true`  |
| `password_profile.require_digit`    | Requires at least one digit                                                | `true`  |
| `password_profile.require_special`  | Requires at least one special character                                    | `false` |
| `password_profile.expiration_days`  | Number of days until password expires (0 disables)                         | `0`     |
| `password_profile.grace_days`       | Additional grace period in days after expiration                           | `0`     |
| `password_profile.reuse_time_days`  | Minimum days before a password can be reused                               | `0`     |
| `password_profile.reuse_max`        | Number of previous passwords disallowed                                    | `3`     |
| `password_profile.enable_blacklist`| Enables password blacklist validation                                      | `true`  |
| `password_profile.failed_login_max`| Max failed login attempts before lockout                                   | `10`    |
| `password_profile.lockout_time_mins`| Lockout duration in minutes                                                | `1440`  |
| `password_profile.allow_hashed`     | Allows hashed passwords to bypass checks                                   | `false` |
| `password_profile.verify_function`  | Custom SQL function for additional password checks                         | `""`    |

Example:

```sql
ALTER SYSTEM SET password_profile.min_length = 12;
ALTER SYSTEM SET password_profile.failed_login_max = 5;
SELECT pg_reload_conf();
```

---

## 🧱 Blacklist Usage

Add weak passwords using:

```sql
INSERT INTO password_profile.blacklist (word) VALUES
('123456'),
('password'),
('qwerty'),
('12345678');
```

---

## ❌ Uninstallation

1. Remove from `shared_preload_libraries` in `postgresql.conf`
2. Restart PostgreSQL:
   ```bash
   sudo systemctl restart postgresql-16
   ```
3. Remove schema:
   ```sql
   DROP SCHEMA password_profile CASCADE;
   ```
4. Optionally uninstall files:
   ```bash
   sudo make uninstall
   
