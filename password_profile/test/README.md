# Password Profile Pure - Test Suite

Automated test suite for validating all password policy features.

## Quick Start

```bash
# Run all tests
cd test
./run_tests.sh

# Run specific test
psql -f sql/01_password_complexity.sql
```

## Test Coverage

### 1. Password Complexity (`01_password_complexity.sql`)
- Minimum length validation
- Uppercase/lowercase requirements
- Digit requirement
- Special character requirement
- Username prevention

### 2. Password History (`02_password_history.sql`)
- Password reuse prevention
- History count enforcement
- Reuse interval restriction
- Password stats retrieval

### 3. Failed Login Lockout (`03_failed_login_lockout.sql`)
- Failed login tracking
- Lockout threshold enforcement
- Lockout duration
- Manual unlock (superuser)

### 4. Blacklist Validation (`04_blacklist.sql`)
- File-based blacklist (9,789 passwords)
- Database blacklist (dynamic)
- Add/remove blacklist entries

### 5. Password Expiration (`05_password_expiration.sql`)
- Expiration date tracking
- Grace login period
- Expiry check
- Password rotation

### 6. Security Permissions (`06_security_permissions.sql`)
- User permission checks
- Superuser privileges
- Cross-user access denial

### 7. User-Level GUC Configuration (`07_user_level_guc.sql`)
- Per-user password policies
- ALTER ROLE SET configuration
- Policy inheritance verification
- Reset configuration testing

## Test Results

Results are stored in `test/results/` directory. 

To regenerate baseline expected outputs:
```bash
rm -rf test/expected/*
./run_tests.sh  # Creates new baseline
```

## Continuous Integration

Add to your CI/CD pipeline:
```yaml
# Example: GitHub Actions
- name: Run Extension Tests
  run: |
    cd password_profile_pure/test
    ./run_tests.sh
```

## Manual Testing

```bash
# Test specific feature
psql -c "SELECT check_password('user', 'weak');"

# Monitor failed logins
psql -c "SELECT * FROM password_profile.login_attempts;"

# Check lockout status
psql -c "SELECT is_user_locked('testuser');"
```

## Troubleshooting

### Test fails with "extension not found"
```bash
# Install extension first
psql -c "CREATE EXTENSION password_profile_pure;"
```

### Permission denied errors
```bash
# Run as PostgreSQL superuser
sudo -u postgres ./run_tests.sh
```

### Different output than expected
```bash
# Compare actual vs expected
diff -u test/expected/01_password_complexity.out \
        test/results/01_password_complexity.out
```
