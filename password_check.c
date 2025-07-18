#include "postgres.h"
#include "fmgr.h"

/* * Required Header Files for various PostgreSQL functionalities.
 */
#include "storage/lwlock.h"      // For Lightweight Locks, used for concurrency control.
#include "storage/shmem.h"       // For shared memory management.
#include "storage/proc.h"        // For accessing process information.
#include "utils/hsearch.h"       // For managing hash tables in shared memory.
#include "miscadmin.h"           // For server-wide administration functions like GUCs.
#include "executor/spi.h"        // For Server Programming Interface, allowing SQL queries from C.
#include "utils/builtins.h"      // For various built-in utility functions (e.g., text conversion).
#include "utils/timestamp.h"     // For timestamp-related functions.
#include "commands/user.h"       // For user and role management functions.
#include "utils/guc.h"           // For Grand Unified Configuration (GUC) management.
#include "libpq/auth.h"          // For authentication hooks and structures.
#include "catalog/pg_authid.h"   // For role/user catalog access.
#include "utils/lsyscache.h"     // For system cache access (e.g., getting OIDs).
#include <ctype.h>               // Standard C library for character type functions (isupper, etc.).

/*
 * This macro is required by PostgreSQL for any dynamically loaded module.
 * It provides version control and ensures module compatibility.
 */
PG_MODULE_MAGIC;

/*
 * MANUAL DECLARATIONS
 * These are included as a fallback in case the compiler has issues
 * reading the declarations from the standard header files. This can happen
 * with different PostgreSQL versions or build environments.
 */
extern Oid get_role_oid(const char *rolename, bool missing_ok);
extern PGDLLIMPORT void (*shmem_request_hook) (void);
extern PGDLLIMPORT void (*shmem_startup_hook) (void);

/* ---- Hook Function Prototypes ---- */
// This function requests shared memory during server startup.
static void password_check_shmem_request(void);
// This function initializes the data structures in the allocated shared memory.
static void password_check_shmem_startup(void);
// This is the authentication hook that checks for login lockouts.
static void check_login_attempts(Port *port, int status);
// This is the password validation hook that checks password policies.
static void my_check_password_hook(const char *username, const char *password, PasswordType password_type,
                                   Datum validuntil_time, bool validuntil_null);

/* ---- Pointers to Store Previous Hooks ---- */
// Storing the previous hooks allows us to chain them, ensuring that other extensions
// or PostgreSQL's own functionality that use these hooks are not broken.
static void (*prev_shmem_request_hook)(void) = NULL;
static void (*prev_shmem_startup_hook)(void) = NULL;
static check_password_hook_type prev_check_password_hook = NULL;
static ClientAuthentication_hook_type prev_client_auth_hook = NULL;


/* ---- Global Structs and State ---- */

/*
 * Stores information about a user's login attempts in shared memory.
 * This struct defines the data we track for each user with failed logins.
 * REVISION: Added 'lockout_start_time' to implement a fixed-duration lockout.
 */
typedef struct LoginAttempt
{
    char        username[NAMEDATALEN];      // The user's name (key for the hash table).
    int         fail_count;                 // The number of consecutive failed login attempts.
    TimestampTz lockout_start_time;       // Stores the exact time the lockout began.
} LoginAttempt;

/* * Holds the global state for this extension, which resides in shared memory. 
 * This allows the state to be persistent across all backend processes.
 */
typedef struct LoginAttemptState
{
    LWLock *lock;                   // A lightweight lock to prevent race conditions when accessing the hash table.
    HTAB   *login_attempts_hash;    // The hash table that stores LoginAttempt structs.
} LoginAttemptState;

// A global pointer to our shared state. It's NULL in a new backend until initialized.
static LoginAttemptState *login_state = NULL;

/* ---- GUC (Grand Unified Configuration) Variables ---- */
// These variables are configurable parameters that can be set in postgresql.conf.
int         password_min_length = 8;        // Minimum password length.
int         password_expiration_days = 0;   // Days until password expires. 0 to disable.
int         password_grace_days = 0;        // Grace period in days after expiration.
int         password_reuse_time_days = 0;   // Days before a password can be reused.
int         password_reuse_max = 3;         // Number of old passwords that cannot be reused.
bool        password_require_upper = true;  // Must contain an uppercase letter.
bool        password_require_lower = true;  // Must contain a lowercase letter.
bool        password_require_digit = true;  // Must contain a digit.
bool        password_require_special = false; // Must contain a special character.
bool        password_enable_blacklist = true; // Enable checking against the blacklist table.
bool        password_allow_hashed = false;    // If true, skip checks for pre-hashed passwords (MD5/SCRAM).
char       *password_verify_function = NULL;  // An optional custom function for password validation.
int         password_failed_login_max = 10;   // Max failed logins before account lockout.
int         password_lockout_time_mins = 1440; // Lockout duration in minutes.

/* ---- Hook Functions ---- */

/*
 * Request shared memory space and locks at server startup.
 * This must be registered to the shmem_request_hook.
 * It's one of the first hooks to run when PostgreSQL starts.
 */
static void
password_check_shmem_request(void)
{
    // Chain to the previous hook, if it exists.
    if (prev_shmem_request_hook)
        prev_shmem_request_hook();

    // Request a chunk of shared memory for our extension's state.
    RequestAddinShmemSpace(sizeof(LoginAttemptState));
    // Request a named lock tranche for our extension to use for synchronization.
    RequestNamedLWLockTranche("password_check", 1);
}

/*
 * Initialize the shared memory hash table.
 * This must be registered to the shmem_startup_hook.
 * It runs after shared memory has been allocated, but before backends start accepting connections.
 */
static void
password_check_shmem_startup(void)
{
    bool        found;
    HASHCTL     ctl;

    // Chain to the previous hook.
    if (prev_shmem_startup_hook)
        prev_shmem_startup_hook();

    // Attach to or initialize the shared memory structure for our extension.
    login_state = (LoginAttemptState *) ShmemInitStruct("password_check_login_state",
                                                        sizeof(LoginAttemptState),
                                                        &found);

    // If 'found' is false, this is the first time, so we need to initialize the contents.
    if (!found)
    {
        // Initialize the lock pointer.
        login_state->lock = &(GetNamedLWLockTranche("password_check")[0].lock);
        
        // Set up the control structure for the hash table.
        memset(&ctl, 0, sizeof(ctl));
        ctl.keysize = NAMEDATALEN;
        ctl.entrysize = sizeof(LoginAttempt);
        
        // Initialize the hash table in shared memory.
        login_state->login_attempts_hash = ShmemInitHash("Login Attempts Hash Table",
                                                         128,  // Initial size
                                                         1024, // Max size
                                                         &ctl,
                                                         HASH_ELEM | HASH_STRINGS);
    }
}


/*
 * Main authentication hook function. Checks for lockouts and records failures.
 * This function is called by the postmaster for every connection attempt.
 * REVISION: Logic was rewritten to prevent the lockout timer from resetting on subsequent failed attempts.
 */
static void
check_login_attempts(Port *port, int status)
{
    const char *username = port->user_name;
    Oid         user_oid;
    LoginAttempt *attempt;
    bool        found;

    // If there's no username, we can't do anything.
    if (!username)
    {
        if (prev_client_auth_hook) prev_client_auth_hook(port, status);
        return;
    }
    
    // Do not apply lockout policy to superusers.
    user_oid = get_role_oid(username, true);
    if (!OidIsValid(user_oid) || superuser_arg(user_oid))
    {
        if (prev_client_auth_hook) prev_client_auth_hook(port, status);
        return;
    }

    // Acquire an exclusive lock to ensure safe concurrent access to shared memory.
    LWLockAcquire(login_state->lock, LW_EXCLUSIVE);

    // Look for the user in our hash table of failed login attempts.
    attempt = (LoginAttempt *) hash_search(login_state->login_attempts_hash,
                                           username, HASH_FIND, &found);

    /* Step 1: Check if the user is currently locked and if the lockout has expired. */
    if (found && attempt->fail_count >= password_failed_login_max)
    {
        // Calculate when the lockout period ends.
        TimestampTz lock_until = TimestampTzPlusMilliseconds(attempt->lockout_start_time,
                                                             (long) password_lockout_time_mins * 60 * 1000);

        // Compare with the current time.
        if (GetCurrentTimestamp() < lock_until)
        {
            /* Still locked. Reject connection. This block prevents the timer from resetting. */
            LWLockRelease(login_state->lock);
            // Report a FATAL error, which terminates the connection attempt.
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
        /* Successful login. Clean up any old non-locking failure records for this user. */
        if (found)
        {
            hash_search(login_state->login_attempts_hash, username, HASH_REMOVE, NULL);
        }
    }
    else /* status != STATUS_OK, FAILED LOGIN */
    {
        /* Find or create the record for the user. HASH_ENTER will create if not found. */
        attempt = (LoginAttempt *) hash_search(login_state->login_attempts_hash,
                                               username, HASH_ENTER, &found);
        if (!found)
        {
            /* This is the first failed attempt for this user, so initialize the record. */
            attempt->fail_count = 0;
            attempt->lockout_start_time = 0; /* Initialize timestamp to zero */
        }

        // Increment the failure count.
        attempt->fail_count++;

        /* If THIS attempt triggers the lockout, SET the lockout start time ONCE. */
        if (attempt->fail_count == password_failed_login_max)
        {
            attempt->lockout_start_time = GetCurrentTimestamp();
        }
    }

    // Always release the lock.
    LWLockRelease(login_state->lock);

    // Call the next hook in the chain to continue the authentication process.
    if (prev_client_auth_hook)
        prev_client_auth_hook(port, status);
}

/*
 * Checks a password against basic complexity policies.
 * Returns true if the password is valid, false otherwise.
 * The reason for failure is returned via the 'reason' output parameter.
 */
static bool
validate_password_policy(const char *username, const char *password, const char **reason)
{
    bool has_upper = false, has_lower = false, has_digit = false, has_special = false;
    int i, ulen = strlen(username), plen = strlen(password);
    char uname_lower[256], pass_lower[256];

    // First, iterate through the password to check for character types.
    for (i = 0; password[i]; i++) {
        if (isupper((unsigned char)password[i])) has_upper = true;
        else if (islower((unsigned char)password[i])) has_lower = true;
        else if (isdigit((unsigned char)password[i])) has_digit = true;
        else if (ispunct((unsigned char)password[i])) has_special = true;
    }

    // Check minimum length.
    if (plen < password_min_length) {
        *reason = "Password is too short.";
        return false;
    }
    // Check for uppercase letter if required.
    if (password_require_upper && !has_upper) {
        *reason = "Password must contain at least one uppercase letter.";
        return false;
    }
    // Check for lowercase letter if required.
    if (password_require_lower && !has_lower) {
        *reason = "Password must contain at least one lowercase letter.";
        return false;
    }
    // Check for digit if required.
    if (password_require_digit && !has_digit) {
        *reason = "Password must contain at least one digit.";
        return false;
    }
    // Check for special character if required.
    if (password_require_special && !has_special) {
        *reason = "Password must contain at least one special character.";
        return false;
    }

    // Check if the password contains the username (case-insensitive).
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

    // If all checks passed, the policy is satisfied.
    return true;
}

/*
 * Uses SPI to check if the password exists in the blacklist table.
 */
static bool
is_password_blacklisted(const char *password)
{
    char        query[1024];

    // Construct the SQL query. quote_literal_cstr prevents SQL injection.
    snprintf(query, sizeof(query),
             "SELECT 1 FROM password_check.blacklist WHERE word = %s",
             quote_literal_cstr(password));

    // Execute the query.
    if (SPI_execute(query, true, 1) != SPI_OK_SELECT)
        elog(ERROR, "SPI_execute failed (blacklist)");

    // If any rows are returned, the password is in the blacklist.
    return (SPI_processed > 0);
}

/*
 * Uses SPI to check if the user's password has expired.
 */
static bool
is_password_expired(const char *username)
{
    char        query[1024];

    // Construct a query to find the most recent password change date and see if it's too old.
    snprintf(query, sizeof(query),
             "SELECT change_date < now() - interval '%d days' "
             "FROM password_check.history WHERE username = %s "
             "ORDER BY change_date DESC LIMIT 1",
             password_expiration_days + password_grace_days,
             quote_literal_cstr(username));

    if (SPI_execute(query, true, 1) != SPI_OK_SELECT)
        elog(ERROR, "SPI_execute failed (expiration)");

    // If a row is returned, extract the boolean result.
    if (SPI_processed == 1)
    {
        bool        isnull;
        Datum       result = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);

        return !isnull && DatumGetBool(result);
    }
    
    // If no history exists for the user, it hasn't expired.
    return false;
}

/*
 * This is the main password checking hook, called by commands like
 * CREATE USER and ALTER USER. It enforces all password policies.
 */
static void
my_check_password_hook(const char *username, const char *password, PasswordType password_type,
                       Datum validuntil_time, bool validuntil_null)
{
    int         ret;
    char        query[2048];
    const char *reason = NULL;

    // If configured, allow pre-hashed passwords to skip plaintext checks.
#ifdef PASSWORD_TYPE_SCRAM
    if (password_allow_hashed &&
        (password_type == PASSWORD_TYPE_MD5 || password_type == PASSWORD_TYPE_SCRAM))
        return;
#else
    if (password_allow_hashed &&
        password_type == PASSWORD_TYPE_MD5)
        return;
#endif

    // Perform basic complexity validation first.
    if (!validate_password_policy(username, password, &reason))
        // If it fails, throw an error, which cancels the CREATE/ALTER USER command.
        ereport(ERROR, (errcode(ERRCODE_INVALID_PASSWORD),
                        errmsg("Password validation failed: %s", reason)));

    // Connect to the Server Programming Interface to run SQL queries.
    if (SPI_connect() != SPI_OK_CONNECT)
        elog(ERROR, "SPI_connect failed");

    // If a custom verification function is defined, call it.
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

    // Check against the password blacklist.
    if (password_enable_blacklist && is_password_blacklisted(password))
    {
        SPI_finish();
        ereport(ERROR, (errcode(ERRCODE_INVALID_PASSWORD),
                        errmsg("Password is too common (blacklisted).")));
    }

    // Check if the current password has expired.
    if (password_expiration_days > 0 && is_password_expired(username))
    {
        SPI_finish();
        ereport(ERROR, (errcode(ERRCODE_INVALID_PASSWORD),
                        errmsg("Password has expired. Please set a new one.")));
    }

    // Check password history for reuse based on time.
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

    // Check password history for reuse based on the last N passwords.
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
    
    // If all checks passed, the new password is valid.
    // Insert the new password's hash into the history table.
    snprintf(query, sizeof(query),
             "INSERT INTO password_check.history(username, password_hash) "
             "VALUES (%s, crypt(%s, gen_salt('bf')))",
             quote_literal_cstr(username), quote_literal_cstr(password));

    if (SPI_execute(query, false, 0) != SPI_OK_INSERT)
        elog(ERROR, "Failed to insert into password history");

    // Clean up old history records, keeping only the N most recent ones.
    snprintf(query, sizeof(query),
             "DELETE FROM password_check.history "
             "WHERE ctid IN (SELECT ctid FROM (SELECT ctid, row_number() OVER "
             "(PARTITION BY username ORDER BY change_date DESC) AS rn "
             "FROM password_check.history WHERE username = %s) t WHERE rn > %d)",
             quote_literal_cstr(username), password_reuse_max);

    SPI_execute(query, false, 0);

    // Disconnect from SPI.
    SPI_finish();
}

/*
 * The module initialization function. This is the entry point of the extension.
 * It is called only once when the library is loaded into a PostgreSQL backend.
 */
void
_PG_init(void)
{
    /* Assign our functions to the PostgreSQL hooks. */

    // Save the existing hook pointer (if any).
    prev_shmem_request_hook = shmem_request_hook;
    // Set the hook to our function.
    shmem_request_hook = password_check_shmem_request;

    prev_shmem_startup_hook = shmem_startup_hook;
    shmem_startup_hook = password_check_shmem_startup;

    prev_check_password_hook = check_password_hook;
    check_password_hook = my_check_password_hook;

    prev_client_auth_hook = ClientAuthentication_hook;
    ClientAuthentication_hook = check_login_attempts;

    /* Define all GUC parameters to make them available in postgresql.conf. */
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

/*
 * The module finalization function. This is called when the extension is unloaded.
 * It's good practice to restore the original hooks to clean up properly.
 */
void
_PG_fini(void)
{
    /* Restore the original hooks on shutdown */
    shmem_request_hook = prev_shmem_request_hook;
    shmem_startup_hook = prev_shmem_startup_hook;
    check_password_hook = prev_check_password_hook;
    ClientAuthentication_hook = prev_client_auth_hook;
}
