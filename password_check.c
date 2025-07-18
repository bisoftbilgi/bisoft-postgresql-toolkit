#include "postgres.h"
#include "fmgr.h"

/* Required Header Files */
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "storage/proc.h"
#include "utils/hsearch.h"
#include "miscadmin.h"
#include "executor/spi.h"
#include "utils/builtins.h"
#include "utils/timestamp.h"
#include "commands/user.h"
#include "utils/guc.h"
#include "libpq/auth.h"
#include "catalog/pg_authid.h"
#include "utils/lsyscache.h"
#include <ctype.h>

PG_MODULE_MAGIC;

/*
 * MANUAL DECLARATIONS
 * These are included as a fallback in case the compiler has issues
 * reading the declarations from the standard header files.
 */
extern Oid get_role_oid(const char *rolename, bool missing_ok);
extern PGDLLIMPORT void (*shmem_request_hook) (void);
extern PGDLLIMPORT void (*shmem_startup_hook) (void);

/* ---- Hook Function Prototypes ---- */
static void password_check_shmem_request(void);
static void password_check_shmem_startup(void);
static void check_login_attempts(Port *port, int status);
static void my_check_password_hook(const char *username, const char *password, PasswordType password_type,
                       Datum validuntil_time, bool validuntil_null);

/* ---- Pointers to Store Previous Hooks ---- */
static void (*prev_shmem_request_hook)(void) = NULL;
static void (*prev_shmem_startup_hook)(void) = NULL;
static check_password_hook_type prev_check_password_hook = NULL;
static ClientAuthentication_hook_type prev_client_auth_hook = NULL;


/* ---- Global Structs and State ---- */

/*
 * Stores information about a user's login attempts in shared memory.
 * REVISION: Added 'lockout_start_time' to implement a fixed-duration lockout.
 */
typedef struct LoginAttempt
{
    char        username[NAMEDATALEN];
    int         fail_count;
    TimestampTz lockout_start_time; /* Stores the exact time the lockout began. */
} LoginAttempt;

/* Holds the global state for this extension, including the shared memory hash table. */
typedef struct LoginAttemptState
{
    LWLock *lock;
    HTAB   *login_attempts_hash;
} LoginAttemptState;

static LoginAttemptState *login_state = NULL;

/* ---- GUC (Grand Unified Configuration) Variables ---- */
int         password_min_length = 8;
int         password_expiration_days = 0;
int         password_grace_days = 0;
int         password_reuse_time_days = 0;
int         password_reuse_max = 3;
bool        password_require_upper = true;
bool        password_require_lower = true;
bool        password_require_digit = true;
bool        password_require_special = false;
bool        password_enable_blacklist = true;
bool        password_allow_hashed = false;
char       *password_verify_function = NULL;
int         password_failed_login_max = 10;
int         password_lockout_time_mins = 1440;


/* ---- Hook Functions ---- */

/*
 * Request shared memory space and locks at server startup.
 * Must be registered to the shmem_request_hook.
 */
static void
password_check_shmem_request(void)
{
    if (prev_shmem_request_hook)
        prev_shmem_request_hook();

    RequestAddinShmemSpace(sizeof(LoginAttemptState));
    RequestNamedLWLockTranche("password_check", 1);
}

/*
 * Initialize the shared memory hash table.
 * Must be registered to the shmem_startup_hook.
 */
static void
password_check_shmem_startup(void)
{
    bool        found;
    HASHCTL     ctl;

    if (prev_shmem_startup_hook)
        prev_shmem_startup_hook();

    login_state = (LoginAttemptState *) ShmemInitStruct("password_check_login_state",
                                                        sizeof(LoginAttemptState),
                                                        &found);

    if (!found)
    {
        login_state->lock = &(GetNamedLWLockTranche("password_check")[0].lock);
        memset(&ctl, 0, sizeof(ctl));
        ctl.keysize = NAMEDATALEN;
        ctl.entrysize = sizeof(LoginAttempt);
        login_state->login_attempts_hash = ShmemInitHash("Login Attempts Hash Table",
                                                         128, 1024, &ctl,
                                                         HASH_ELEM | HASH_STRINGS);
    }
}


/*
 * Main authentication hook function. Checks for lockouts and records failures.
 * REVISION: Logic was rewritten to prevent the lockout timer from resetting.
 */
static void
check_login_attempts(Port *port, int status)
{
    const char *username = port->user_name;
    Oid         user_oid;
    LoginAttempt *attempt;
    bool        found;

    if (!username)
    {
        if (prev_client_auth_hook) prev_client_auth_hook(port, status);
        return;
    }
    user_oid = get_role_oid(username, true);
    if (!OidIsValid(user_oid) || superuser_arg(user_oid))
    {
        if (prev_client_auth_hook) prev_client_auth_hook(port, status);
        return;
    }

    LWLockAcquire(login_state->lock, LW_EXCLUSIVE);

    attempt = (LoginAttempt *) hash_search(login_state->login_attempts_hash,
                                           username, HASH_FIND, &found);

    /* Step 1: Check if the user is currently locked and if the lockout has expired. */
    if (found && attempt->fail_count >= password_failed_login_max)
    {
        TimestampTz lock_until = TimestampTzPlusMilliseconds(attempt->lockout_start_time,
                                           (long) password_lockout_time_mins * 60 * 1000);

        if (GetCurrentTimestamp() < lock_until)
        {
            /* Still locked. Reject connection. This block prevents the timer from resetting. */
            LWLockRelease(login_state->lock);
            ereport(FATAL, (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
                            errmsg("User account is temporarily locked. Please try again later.")));
        }
        else
        {
            /* Lockout has expired. Delete the record and allow the login attempt to proceed. */
            hash_search(login_state->login_attempts_hash, username, HASH_REMOVE, NULL);
            found = false; /* The record no longer exists */
        }
    }

    /* Step 2: After resolving lock status, process the current login attempt. */
    if (status == STATUS_OK)
    {
        /* Successful login. Clean up any old non-locking failure records. */
        if (found)
        {
            hash_search(login_state->login_attempts_hash, username, HASH_REMOVE, NULL);
        }
    }
    else /* status != STATUS_OK, FAILED LOGIN */
    {
        /* Find or create the record for the user. */
        attempt = (LoginAttempt *) hash_search(login_state->login_attempts_hash,
                                               username, HASH_ENTER, &found);
        if (!found)
        {
            /* This is the first failed attempt for this user, initialize the counter. */
            attempt->fail_count = 0;
            attempt->lockout_start_time = 0; /* Initialize timestamp to zero */
        }

        attempt->fail_count++;

        /* If THIS attempt triggers the lockout, SET the lockout start time ONCE. */
        if (attempt->fail_count == password_failed_login_max)
        {
            attempt->lockout_start_time = GetCurrentTimestamp();
        }
    }

    LWLockRelease(login_state->lock);

    /* Call the next hook in the chain. */
    if (prev_client_auth_hook)
        prev_client_auth_hook(port, status);
}

static bool
validate_password_policy(const char *username, const char *password, const char **reason)
{
    bool has_upper = false, has_lower = false, has_digit = false, has_special = false;
    int i, ulen = strlen(username), plen = strlen(password);
    char uname_lower[256], pass_lower[256];

    for (i = 0; password[i]; i++) {
        if (isupper((unsigned char)password[i])) has_upper = true;
        else if (islower((unsigned char)password[i])) has_lower = true;
        else if (isdigit((unsigned char)password[i])) has_digit = true;
        else if (ispunct((unsigned char)password[i])) has_special = true;
    }

    if (plen < password_min_length) {
        *reason = "Password is too short.";
        return false;
    }
    if (password_require_upper && !has_upper) {
        *reason = "Password must contain at least one uppercase letter.";
        return false;
    }
    if (password_require_lower && !has_lower) {
        *reason = "Password must contain at least one lowercase letter.";
        return false;
    }
    if (password_require_digit && !has_digit) {
        *reason = "Password must contain at least one digit.";
        return false;
    }
    if (password_require_special && !has_special) {
        *reason = "Password must contain at least one special character.";
        return false;
    }

    if (ulen < sizeof(uname_lower) && plen < sizeof(pass_lower)) {
        for (i = 0; i < ulen; i++) uname_lower[i] = tolower((unsigned char)username[i]);
        uname_lower[ulen] = '\0';
        for (i = 0; i < plen; i++) pass_lower[i] = tolower((unsigned char)password[i]);
        pass_lower[plen] = '\0';

        if (strstr(pass_lower, uname_lower) != NULL) {
            *reason = "Password must not contain the username.";
            return false;
        }
    }

    return true;
}

static bool
is_password_blacklisted(const char *password)
{
    char        query[1024];

    snprintf(query, sizeof(query),
             "SELECT 1 FROM password_check.blacklist WHERE word = %s",
             quote_literal_cstr(password));

    if (SPI_execute(query, true, 1) != SPI_OK_SELECT)
        elog(ERROR, "SPI_execute failed (blacklist)");

    return (SPI_processed > 0);
}

static bool
is_password_expired(const char *username)
{
    char        query[1024];

    snprintf(query, sizeof(query),
             "SELECT change_date < now() - interval '%d days' "
             "FROM password_check.history WHERE username = %s "
             "ORDER BY change_date DESC LIMIT 1",
             password_expiration_days + password_grace_days,
             quote_literal_cstr(username));

    if (SPI_execute(query, true, 1) != SPI_OK_SELECT)
        elog(ERROR, "SPI_execute failed (expiration)");

    if (SPI_processed == 1)
    {
        bool        isnull;
        Datum       result = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);

        return !isnull && DatumGetBool(result);
    }

    return false;
}

static void
my_check_password_hook(const char *username, const char *password, PasswordType password_type,
                       Datum validuntil_time, bool validuntil_null)
{
    int         ret;
    char        query[2048];
    const char *reason = NULL;

#ifdef PASSWORD_TYPE_SCRAM
    if (password_allow_hashed &&
        (password_type == PASSWORD_TYPE_MD5 || password_type == PASSWORD_TYPE_SCRAM))
        return;
#else
    if (password_allow_hashed &&
        password_type == PASSWORD_TYPE_MD5)
        return;
#endif

    if (!validate_password_policy(username, password, &reason))
        ereport(ERROR, (errcode(ERRCODE_INVALID_PASSWORD),
                        errmsg("Password validation failed: %s", reason)));

    if (SPI_connect() != SPI_OK_CONNECT)
        elog(ERROR, "SPI_connect failed");

    if (password_verify_function && strlen(password_verify_function) > 0)
    {
        Oid         argtypes[2] = {TEXTOID, TEXTOID};
        Datum       values[2] = {
            CStringGetTextDatum(username),
            CStringGetTextDatum(password)
        };

        ret = SPI_execute_with_args(
                                    psprintf("SELECT %s($1, $2)", password_verify_function),
                                    2, argtypes, values, NULL, true, 1
            );

        if (ret != SPI_OK_SELECT)
            elog(ERROR, "Failed to call verify function");
    }

    if (password_enable_blacklist && is_password_blacklisted(password))
    {
        SPI_finish();
        ereport(ERROR, (errcode(ERRCODE_INVALID_PASSWORD),
                        errmsg("Password is too common (blacklisted).")));
    }

    if (password_expiration_days > 0 && is_password_expired(username))
    {
        SPI_finish();
        ereport(ERROR, (errcode(ERRCODE_INVALID_PASSWORD),
                        errmsg("Password has expired. Please set a new one.")));
    }

    snprintf(query, sizeof(query),
             "SELECT 1 FROM password_check.history "
             "WHERE username = %s AND password_hash = crypt(%s, password_hash) "
             "AND change_date > now() - interval '%d days'",
             quote_literal_cstr(username), quote_literal_cstr(password),
             password_reuse_time_days);

    if (password_reuse_time_days > 0 &&
        SPI_execute(query, true, 1) == SPI_OK_SELECT && SPI_processed > 0)
    {
        SPI_finish();
        ereport(ERROR, (errcode(ERRCODE_INVALID_PASSWORD),
                        errmsg("Password has been used recently.")));
    }

    snprintf(query, sizeof(query),
             "SELECT 1 FROM (SELECT password_hash FROM password_check.history "
             "WHERE username = %s ORDER BY change_date DESC LIMIT %d) sub "
             "WHERE password_hash = crypt(%s, password_hash)",
             quote_literal_cstr(username), password_reuse_max,
             quote_literal_cstr(password));

    if (SPI_execute(query, true, 1) != SPI_OK_SELECT)
        elog(ERROR, "SPI_execute failed (reuse max)");

    if (SPI_processed > 0)
    {
        SPI_finish();
        ereport(ERROR, (errcode(ERRCODE_INVALID_PASSWORD),
                        errmsg("Password must not match the last %d passwords.", password_reuse_max)));
    }

    snprintf(query, sizeof(query),
             "INSERT INTO password_check.history(username, password_hash) "
             "VALUES (%s, crypt(%s, gen_salt('bf')))",
             quote_literal_cstr(username), quote_literal_cstr(password));

    if (SPI_execute(query, false, 0) != SPI_OK_INSERT)
        elog(ERROR, "Failed to insert into password history");

    snprintf(query, sizeof(query),
             "DELETE FROM password_check.history "
             "WHERE ctid IN (SELECT ctid FROM (SELECT ctid, row_number() OVER "
             "(PARTITION BY username ORDER BY change_date DESC) AS rn "
             "FROM password_check.history WHERE username = %s) t WHERE rn > %d)",
             quote_literal_cstr(username), password_reuse_max);

    SPI_execute(query, false, 0);

    SPI_finish();
}

void
_PG_init(void)
{
    /* Assign hooks in the correct order */
    prev_shmem_request_hook = shmem_request_hook;
    shmem_request_hook = password_check_shmem_request;

    prev_shmem_startup_hook = shmem_startup_hook;
    shmem_startup_hook = password_check_shmem_startup;

    prev_check_password_hook = check_password_hook;
    check_password_hook = my_check_password_hook;

    prev_client_auth_hook = ClientAuthentication_hook;
    ClientAuthentication_hook = check_login_attempts;

    /* Define all GUC parameters */
    DefineCustomIntVariable("password_check.min_length", NULL, NULL,
                            &password_min_length, 8, 1, 128, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomIntVariable("password_check.expiration_days", NULL, NULL,
                          &password_expiration_days, 0, 0, 3650, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomIntVariable("password_check.grace_days", NULL, NULL,
                            &password_grace_days, 0, 0, 3650, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomIntVariable("password_check.reuse_time_days", NULL, NULL,
                          &password_reuse_time_days, 0, 0, 3650, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomIntVariable("password_check.reuse_max", NULL, NULL,
                            &password_reuse_max, 3, 1, 100, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomBoolVariable("password_check.require_upper", NULL, NULL,
                             &password_require_upper, true, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomBoolVariable("password_check.require_lower", NULL, NULL,
                             &password_require_lower, true, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomBoolVariable("password_check.require_digit", NULL, NULL,
                             &password_require_digit, true, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomBoolVariable("password_check.require_special", NULL, NULL,
                             &password_require_special, false, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomBoolVariable("password_check.enable_blacklist", NULL, NULL,
                           &password_enable_blacklist, true, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomBoolVariable("password_check.allow_hashed", NULL, NULL,
                             &password_allow_hashed, false, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomStringVariable("password_check.verify_function", NULL, NULL,
                               &password_verify_function, "", PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomIntVariable("password_check.failed_login_max", NULL, NULL,
                          &password_failed_login_max, 10, 1, 100, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomIntVariable("password_check.lockout_time_mins", NULL, NULL,
                          &password_lockout_time_mins, 1440, 1, 10080, PGC_SUSET, 0, NULL, NULL, NULL);
}

void
_PG_fini(void)
{
    /* Restore the original hooks on shutdown */
    shmem_request_hook = prev_shmem_request_hook;
    shmem_startup_hook = prev_shmem_startup_hook;
    check_password_hook = prev_check_password_hook;
    ClientAuthentication_hook = prev_client_auth_hook;
}
