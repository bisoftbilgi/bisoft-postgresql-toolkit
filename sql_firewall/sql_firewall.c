/*
 * SQL FIREWALL - FINAL PROJECT CODE
 * Compiler warnings have been resolved.
 */

#include <stdbool.h>
#include <ctype.h>
#include "postgres.h"
#include "fmgr.h"
#include "access/xact.h"
#include "executor/spi.h"
#include "tcop/utility.h"
#include "executor/executor.h"
#include "utils/guc.h"
#include "utils/syscache.h"
#include "utils/builtins.h"
#include "parser/parse_node.h"
#include "nodes/parsenodes.h"
#include "utils/varlena.h"

// External function prototypes from PostgreSQL backend
extern bool superuser(void);
extern Oid GetUserId(void);
extern char *GetUserNameFromId(Oid roleid, bool noerror);

// Required macro for a PostgreSQL extension
PG_MODULE_MAGIC;

// Forward declarations for module initialization and finalization functions
void _PG_init(void);
void _PG_fini(void);

// Pointers to save the previous hook functions, allowing us to chain calls.
static ExecutorStart_hook_type prev_executor_start_hook = NULL;
static ProcessUtility_hook_type prev_process_utility_hook = NULL;

// --- Global Configuration Variables (GUCs) ---
// These variables are set by PostgreSQL based on postgresql.conf settings.

// Firewall operational mode (learn, permissive, enforce)
static int sql_firewall_mode;
// Re-entrancy flag to prevent nested calls to the firewall logic
static bool inside_firewall = false;
// Flag to enable or disable keyword scanning
static bool enable_keyword_scan;
// Comma-separated list of keywords to block
static char *blacklisted_keywords;
// Flag to enable or disable quiet hours
static bool enable_quiet_hours;
// Start time for quiet hours (HH:MM format)
static char *quiet_hours_start;
// End time for quiet hours (HH:MM format)
static char *quiet_hours_end;
// Flag to enable or disable general rate limiting
static bool enable_rate_limiting;
// Number of queries allowed within the rate limit window
static int rate_limit_count;
// Time window in seconds for the general rate limit
static int rate_limit_seconds;
// Flag to enable or disable regex-based scanning
static bool enable_regex_scan;

// Per-command rate limit counts
static int select_limit_count;
static int insert_limit_count;
static int update_limit_count;
static int delete_limit_count;
// Time window in seconds for per-command rate limits
static int command_limit_seconds;

// Flag to enable or disable application blocking
static bool enable_application_blocking;
// Comma-separated list of application names to block
static char *blocked_applications;

// Enum for the different modes of the SQL firewall
typedef enum {
    SQL_FIREWALL_MODE_LEARN,      // Learn new queries and add them to the ruleset
    SQL_FIREWALL_MODE_PERMISSIVE, // Log but allow unknown queries
    SQL_FIREWALL_MODE_ENFORCE     // Block unknown or unapproved queries
} SqlFirewallMode;

// Options for the sql_firewall.mode GUC, displayed in pg_settings
static const struct config_enum_entry mode_options[] = {
    {"learn", SQL_FIREWALL_MODE_LEARN, false},
    {"permissive", SQL_FIREWALL_MODE_PERMISSIVE, false},
    {"enforce", SQL_FIREWALL_MODE_ENFORCE, false},
    {NULL, 0, false}
};

/**
 * @brief Computes a hash of the given string using the djb2 algorithm.
 * @param str The input string (query text).
 * @return A 64-bit hash value.
 */
static uint64 hash_query(const char *str)
{
    uint64 hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    return hash;
}

/**
 * @brief Checks if the query string contains any blacklisted keywords.
 * @param query_string The SQL query to check.
 * @return The first blacklisted keyword found, or NULL if none are found.
 */
static const char* contains_blacklisted_keyword(const char *query_string)
{
    static char found[128]; // Static buffer to return the found keyword
    char *copy, *kw, *token, *end;
    int i;

    if (!enable_keyword_scan || !blacklisted_keywords)
        return NULL;

    // Work on a lowercase copy to make the search case-insensitive
    copy = pstrdup(query_string);
    for (i = 0; copy[i]; i++)
        copy[i] = tolower(copy[i]);

    // Tokenize the list of blacklisted keywords
    kw = pstrdup(blacklisted_keywords);
    token = strtok(kw, ",");

    while (token)
    {
        // Trim leading/trailing whitespace from the token
        while (isspace((unsigned char)*token)) token++;
        end = token + strlen(token) - 1;
        while (end > token && isspace((unsigned char)*end)) *end-- = '\0';

        // If the keyword is found in the query, return it
        if (strstr(copy, token))
        {
            strncpy(found, token, sizeof(found)-1);
            found[sizeof(found)-1] = '\0';
            pfree(copy); pfree(kw);
            return found;
        }
        token = strtok(NULL, ",");
    }

    pfree(copy); pfree(kw);
    return NULL;
}

/**
 * @brief Checks if the current time is within the configured quiet hours.
 * @return True if it's currently quiet hours, false otherwise.
 */
static bool is_in_quiet_hours(void)
{
    bool result = false;
    int h=0, m=0, sh=0, sm=0, eh=0, em=0;
    char *time_str = NULL;
    int curr = 0, start = 0, end = 0;
    bool spi_started = false;

    if (!enable_quiet_hours)
        return false;

    PG_TRY();
    {
        if (SPI_connect() == SPI_OK_CONNECT)
        {
            spi_started = true;
            // Get current time from the database as 'HH24:MI'
            if (SPI_execute("SELECT to_char(now(), 'HH24:MI')", true, 0) == SPI_OK_SELECT && SPI_processed > 0)
            {
                time_str = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
                if (time_str)
                {
                    sscanf(time_str, "%d:%d", &h, &m);
                    sscanf(quiet_hours_start, "%d:%d", &sh, &sm);
                    sscanf(quiet_hours_end, "%d:%d", &eh, &em);
                    
                    // Convert times to minutes from midnight for easy comparison
                    curr = h * 60 + m;
                    start = sh * 60 + sm;
                    end = eh * 60 + em;
                    
                    // Handle overnight ranges (e.g., 22:00 to 06:00) where end time is earlier than start time
                    result = (start < end) ? (curr >= start && curr < end) : (curr >= start || curr < end);
                }
            }
            SPI_finish();
        }
    }
    PG_CATCH();
    {
        // Ensure SPI is cleaned up on error
        if (spi_started)
            SPI_finish();
        FlushErrorState();
        result = false; // Assume not in quiet hours on error
    }
    PG_END_TRY();
    return result;
}

/**
 * @brief Checks if the current application name is in the blocked list.
 * @param current_app_name The name of the application to check.
 * @return The blocked application name if it's in the list, or NULL otherwise.
 */
static const char* is_application_blocked(const char* current_app_name)
{
    static char found_app[128];
    char *blocked_list_copy, *token, *end;

    if (!enable_application_blocking || !blocked_applications || !current_app_name ||
        strlen(blocked_applications) == 0 || strlen(current_app_name) == 0)
        return NULL;

    // Tokenize the comma-separated list of blocked applications
    blocked_list_copy = pstrdup(blocked_applications);
    token = strtok(blocked_list_copy, ",");

    while (token)
    {
        // Trim whitespace from the token
        while (isspace((unsigned char)*token)) token++;
        end = token + strlen(token) - 1;
        while (end > token && isspace((unsigned char)*end)) *end-- = '\0';

        // Compare with the current application name
        if (strcmp(current_app_name, token) == 0)
        {
            strncpy(found_app, token, sizeof(found_app)-1);
            found_app[sizeof(found_app)-1] = '\0';
            pfree(blocked_list_copy);
            return found_app;
        }
        token = strtok(NULL, ",");
    }

    pfree(blocked_list_copy);
    return NULL;
}

/**
 * @brief Returns the specific rate limit for a given command type.
 * @param cmd The command type ("SELECT", "INSERT", etc.).
 * @return The configured rate limit for that command, or 0 if not set.
 */
static int get_command_limit(const char *cmd)
{
    if (strcmp(cmd, "SELECT") == 0) return select_limit_count;
    else if (strcmp(cmd, "INSERT") == 0) return insert_limit_count;
    else if (strcmp(cmd, "UPDATE") == 0) return update_limit_count;
    else if (strcmp(cmd, "DELETE") == 0) return delete_limit_count;
    return 0; // No limit for other commands
}

/**
 * @brief Logs firewall activity to the sql_firewall_activity_log table.
 * @param role The user role performing the action.
 * @param action The action taken by the firewall (e.g., "ALLOWED", "BLOCKED", "LEARNED").
 * @param reason The reason for the action.
 * @param query The full text of the SQL query.
 * @param cmd_type The type of the SQL command (e.g., "SELECT", "UPDATE").
 */
static void log_firewall_action(const char *role, const char *action, const char *reason, const char *query, const char *cmd_type)
{
    Datum vals[6];
    Oid types[6] = {NAMEOID, NAMEOID, TEXTOID, TEXTOID, TEXTOID, TEXTOID};
    char nulls[7] = {' ', ' ', ' ', ' ', ' ', ' ', '\0'}; // ' ' for not null, 'n' for null
    bool spi_is_inside = false;
    char *db_name = NULL;

    PG_TRY();
    {
        if (SPI_connect() == SPI_OK_CONNECT)
        {
            spi_is_inside = true;
            // Get the current database name for logging
            if (SPI_execute("SELECT current_database()", true, 1) == SPI_OK_SELECT && SPI_processed > 0)
                db_name = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);

            // Prepare values for insertion
            vals[0] = CStringGetDatum(role);
            vals[1] = CStringGetDatum(db_name ? db_name : "unknown");
            vals[2] = CStringGetTextDatum(action);
            vals[3] = reason ? CStringGetTextDatum(reason) : (Datum) 0;
            vals[4] = CStringGetTextDatum(query);
            vals[5] = CStringGetTextDatum(cmd_type);

            if (!reason) nulls[3] = 'n'; // Mark reason as NULL if not provided

            // Insert the log record using a parameterized query to prevent SQL injection
            SPI_execute_with_args("INSERT INTO sql_firewall_activity_log (role_name, database_name, action, reason, query_text, command_type) VALUES ($1, $2, $3, $4, $5, $6)",
                                  6, types, vals, nulls, false, 0);
            SPI_finish();
        }
    }
    PG_CATCH();
    {
        // Cleanup on error
        if (spi_is_inside)
            SPI_finish();
        FlushErrorState();
    }
    PG_END_TRY();
}


/**
 * @brief Checks the incoming query against regex rules from the database.
 * @param query_string The SQL query string to check.
 * @return True if the query matches a blocking rule, false otherwise.
 */
static bool query_matches_regex_block_rule(const char *query_string)
{
    bool match_found = false;
    char *sql_get_patterns;
    bool spi_started = false;
    int ret;
    int i;

    // Don't check if the feature is disabled via GUC
    if (!enable_regex_scan)
        return false;

    PG_TRY();
    {
        if (SPI_connect() != SPI_OK_CONNECT)
            elog(ERROR, "SPI_connect failed in regex check");

        spi_started = true;

        // Fetch only active rules with the 'BLOCK' action
        sql_get_patterns = "SELECT pattern FROM sql_firewall_regex_rules WHERE is_active = true AND action = 'BLOCK'";

        ret = SPI_execute(sql_get_patterns, true, 0);

        if (ret != SPI_OK_SELECT)
            elog(ERROR, "SPI_execute failed to get regex rules");

        // Check the query against each rule
        for (i = 0; i < SPI_processed; i++)
        {
            char *pattern;
            Datum match_datum;
            bool is_null;
            char *check_sql;

            // Get the pattern from the table tuple
            pattern = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1);

            if (pattern)
            {
                // Safely check using PostgreSQL's case-insensitive regex operator (~*)
                check_sql = psprintf("SELECT %s ~* %s", quote_literal_cstr(query_string), quote_literal_cstr(pattern));

                ret = SPI_execute(check_sql, true, 1);
                pfree(check_sql); // Free memory allocated by psprintf

                if (ret == SPI_OK_SELECT && SPI_processed > 0)
                {
                    match_datum = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &is_null);
                    if (!is_null && DatumGetBool(match_datum))
                    {
                        // Match found!
                        match_found = true;
                        pfree(pattern);
                        break; // End the loop once a match is found
                    }
                }
                pfree(pattern);
            }
        }

        SPI_finish();
    }
    PG_CATCH();
    {
        if (spi_started)
            SPI_finish();
        FlushErrorState();
        // In case of an error, returning false is the safest default.
        return false;
    }
    PG_END_TRY();

    return match_found;
}

/**
 * @brief The main firewall logic function, called for every query.
 * It performs a series of checks in a specific order.
 * @param query The SQL query string to be checked.
 */
static void check_firewall(const char *query)
{
    const char *cmd = "OTHER";
    List *tree = NULL;
    char *role = GetUserNameFromId(GetUserId(), false);
    uint64 hash;
    Datum vals[4];
    Oid types[4] = {NAMEOID, TEXTOID, INT8OID, NAMEOID};
    bool rule_exists = false, rule_is_approved = false;
    bool spi_started = false;
    int ret;
    const char *kw;
    char *db_name = NULL;
    const char *current_app_name = NULL;
    const char *blocked_app = NULL;
    char *cmd_sql = NULL;

    // Prevent re-entrant calls to avoid infinite loops (e.g., from our own logging queries).
    if (inside_firewall) return;
    inside_firewall = true;

    // RULE 0: Superusers are always exempt from firewall checks. This is a critical safety bypass.
    if (superuser())
    {
        inside_firewall = false;
        return;
    }

    // RULE 1: Check for malicious patterns using regular expressions.
    if (query_matches_regex_block_rule(query))
    {
        log_firewall_action(role, "BLOCKED", "Regex pattern match", query, "UNKNOWN");
        inside_firewall = false; // Reset flag before erroring out
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("sql_firewall: Query blocked due to matching a security regex pattern.")));
    }
    
    // Parse the query to determine its type (SELECT, INSERT, etc.) for logging and rule matching.
    tree = pg_parse_query(query);
    if (tree && list_length(tree) == 1)
    {
        RawStmt *stmt = linitial_node(RawStmt, tree);
        if (IsA(stmt->stmt, InsertStmt)) cmd = "INSERT";
        else if (IsA(stmt->stmt, UpdateStmt)) cmd = "UPDATE";
        else if (IsA(stmt->stmt, DeleteStmt)) cmd = "DELETE";
        else if (IsA(stmt->stmt, SelectStmt)) cmd = "SELECT";
    }

    // RULE 2: Check for blocked applications.
    if (enable_application_blocking)
    {
        current_app_name = GetConfigOptionByName("application_name", NULL, false);
        blocked_app = is_application_blocked(current_app_name);
        if (blocked_app)
        {
            log_firewall_action(role, "BLOCKED", "Blocked application", query, cmd);
            inside_firewall = false;
            ereport(ERROR,
                    (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                     errmsg("sql_firewall: Connections from application '%s' are not allowed.", blocked_app)));
        }
    }

    // RULE 3: Check for general rate limiting.
    if (enable_rate_limiting)
    {
        char *ratelimit_sql;
        int query_count = 0;

        if (SPI_connect() == SPI_OK_CONNECT)
        {
            ratelimit_sql = psprintf(
                "SELECT COUNT(*) FROM sql_firewall_activity_log "
                "WHERE role_name = '%s' AND log_time > now() - interval '%d seconds' AND action <> 'LEARNED'",
                role, rate_limit_seconds);

            if (SPI_execute(ratelimit_sql, true, 1) == SPI_OK_SELECT && SPI_processed > 0)
            {
                char *count_str = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
                if (count_str) query_count = atoi(count_str);
            }
            pfree(ratelimit_sql);
            SPI_finish();

            if (query_count >= rate_limit_count)
            {
                log_firewall_action(role, "BLOCKED", "Rate limit exceeded", query, cmd);
                inside_firewall = false;
                ereport(ERROR, (errmsg("sql_firewall: Rate limit exceeded for role '%s'.", role)));
            }
        }
    }

    // RULE 4: Check for per-command rate limiting.
    if (command_limit_seconds > 0)
    {
        int command_limit = get_command_limit(cmd);
        int cmd_count = 0;

        if (command_limit > 0)
        {
            if (SPI_connect() == SPI_OK_CONNECT)
            {
                cmd_sql = psprintf(
                    "SELECT COUNT(*) FROM sql_firewall_activity_log "
                    "WHERE role_name = '%s' AND command_type = '%s' "
                    "AND log_time > now() - interval '%d seconds'",
                    role, cmd, command_limit_seconds);

                if (SPI_execute(cmd_sql, true, 1) == SPI_OK_SELECT && SPI_processed > 0)
                {
                    char *count_str = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
                    if (count_str) cmd_count = atoi(count_str);
                }

                pfree(cmd_sql);
                SPI_finish();

                if (cmd_count >= command_limit)
                {
                    log_firewall_action(role, "BLOCKED", "Per-command rate limit exceeded", query, cmd);
                    inside_firewall = false;
                    ereport(ERROR, (errmsg("sql_firewall: Rate limit for command '%s' exceeded for role '%s'", cmd, role)));
                }
            }
        }
    }

    // RULE 5: Check for quiet hours.
    if (is_in_quiet_hours())
    {
        log_firewall_action(role, "BLOCKED", "Quiet hours", query, cmd);
        inside_firewall = false;
        ereport(ERROR, (errmsg("sql_firewall: Blocked during quiet hours")));
    }
    
    // RULE 6: Check for blacklisted keywords.
    kw = contains_blacklisted_keyword(query);
    if (kw)
    {
        log_firewall_action(role, "BLOCKED", kw, query, cmd);
        inside_firewall = false;
        ereport(ERROR, (errmsg("sql_firewall: Blocked due to keyword '%s'", kw)));
    }
    
    // RULE 7: Check against the hash-based ruleset.
    hash = hash_query(query);
    PG_TRY();
    {
        if (SPI_connect() == SPI_OK_CONNECT)
        {
            spi_started = true;
            if (SPI_execute("SELECT current_database()", true, 1) == SPI_OK_SELECT && SPI_processed > 0)
                db_name = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);

            vals[0] = CStringGetDatum(role);
            vals[1] = CStringGetTextDatum(cmd);
            vals[2] = UInt64GetDatum(hash);
            vals[3] = CStringGetDatum(db_name ? db_name : "unknown");

            // Check if a rule for this query hash already exists
            ret = SPI_execute_with_args(
                "SELECT is_approved FROM sql_firewall_rules WHERE role_name=$1 AND command_type=$2 AND query_fingerprint=$3 AND database_name=$4",
                4, types, vals, NULL, true, 1);

            if (ret == SPI_OK_SELECT && SPI_processed > 0)
            {
                bool is_null;
                rule_exists = true;
                // Correctly get the boolean value, checking for nulls.
                rule_is_approved = DatumGetBool(SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &is_null));
                if (is_null) rule_is_approved = false;
            }

            // --- Main Firewall Logic (Hash-based) ---
            if (rule_exists && rule_is_approved)
            {
                // Case 1: Rule exists and is approved. Allow the query.
                log_firewall_action(role, "ALLOWED", "Approved rule", query, cmd);
            }
            else if (!rule_exists && sql_firewall_mode == SQL_FIREWALL_MODE_LEARN)
            {
                // Case 2: No rule exists and we are in LEARN mode. Add the new query as a rule and allow.
                log_firewall_action(role, "LEARNED", "New rule", query, cmd);
                SPI_execute_with_args(
                    "INSERT INTO sql_firewall_rules (role_name, command_type, query_fingerprint, database_name) "
                    "VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                    4, types, vals, NULL, false, 0);
            }
            else if (sql_firewall_mode == SQL_FIREWALL_MODE_PERMISSIVE)
            {
                 // Case 3: PERMISSIVE mode. Log the unapproved/unknown query but allow it.
                log_firewall_action(role, "ALLOWED (PERMISSIVE)", rule_exists ? "Rule not approved" : "No rule found", query, cmd);
            }
            else // This defaults to ENFORCE mode
            {
                // Case 4: Block the query. This happens if:
                // - The mode is ENFORCE and no rule is found.
                // - A rule exists, but it is not approved (is_approved = false).
                log_firewall_action(role, "BLOCKED", rule_exists ? "Rule not approved" : "No rule found", query, cmd);
                SPI_finish();
                inside_firewall = false; // Reset flag before erroring out
                ereport(ERROR, (errmsg("sql_firewall: Query not allowed for role '%s'", role)));
            }

            SPI_finish();
        }
    }
    PG_CATCH();
    {
        if (spi_started)
            SPI_finish();
        inside_firewall = false; // Ensure flag is reset on error
        PG_RE_THROW();
    }
    PG_END_TRY();

    // Reset re-entrancy flag before exiting normally
    inside_firewall = false;
}

/**
 * @brief ExecutorStart hook function.
 * This hook is called for DML queries (SELECT, INSERT, UPDATE, DELETE).
 * It calls the main firewall check function.
 */
static void sql_firewall_executor_start_hook(QueryDesc *queryDesc, int eflags)
{
    // Pass the query text to the main firewall logic
    check_firewall(queryDesc->sourceText);

    // Chain to the previous hook or standard executor start
    if (prev_executor_start_hook)
        prev_executor_start_hook(queryDesc, eflags);
    else
        standard_ExecutorStart(queryDesc, eflags);
}

/**
 * @brief ProcessUtility hook function.
 * This hook is called for utility and DDL commands.
 * It calls the main firewall check function.
 */
static void sql_firewall_process_utility_hook(PlannedStmt *pstmt, const char *queryString,
                                              bool readOnlyTree, ProcessUtilityContext context,
                                              ParamListInfo params, QueryEnvironment *queryEnv,
                                              DestReceiver *dest, QueryCompletion *qc)
{
    // Pass the query text to the main firewall logic
    check_firewall(queryString);
    
    // Chain to the previous hook or standard utility processor
    if (prev_process_utility_hook)
        prev_process_utility_hook(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
    else
        standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
}

/**
 * @brief Module initialization function (_PG_init).
 * This function is called when the extension is loaded. It defines all the
 * custom configuration variables (GUCs) and installs the query hooks.
 */
void _PG_init(void)
{
    // Register all custom configuration parameters (GUCs) for the firewall
    DefineCustomEnumVariable("sql_firewall.mode", "Sets the firewall operation mode (learn, permissive, enforce).", NULL, &sql_firewall_mode, SQL_FIREWALL_MODE_LEARN, mode_options, PGC_SUSET, 0, NULL, NULL, NULL);
    
    DefineCustomBoolVariable("sql_firewall.enable_keyword_scan", "Enables scanning for blacklisted keywords.", NULL, &enable_keyword_scan, false, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomStringVariable("sql_firewall.blacklisted_keywords", "Comma-separated list of keywords to block.", NULL, &blacklisted_keywords, "drop,truncate", PGC_SUSET, 0, NULL, NULL, NULL);
    
    DefineCustomBoolVariable("sql_firewall.enable_quiet_hours", "Enables quiet hours during which queries are blocked.", NULL, &enable_quiet_hours, false, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomStringVariable("sql_firewall.quiet_hours_start", "Start time for quiet hours (HH:MM).", NULL, &quiet_hours_start, "22:00", PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomStringVariable("sql_firewall.quiet_hours_end", "End time for quiet hours (HH:MM).", NULL, &quiet_hours_end, "06:00", PGC_SUSET, 0, NULL, NULL, NULL);
    
    DefineCustomBoolVariable("sql_firewall.enable_rate_limiting", "Enables query rate limiting.", NULL, &enable_rate_limiting, false, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomIntVariable("sql_firewall.rate_limit_count", "Number of queries allowed per window.", NULL, &rate_limit_count, 100, 1, INT_MAX, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomIntVariable("sql_firewall.rate_limit_seconds", "Time window for rate limit in seconds.", NULL, &rate_limit_seconds, 60, 1, INT_MAX, PGC_SUSET, 0, NULL, NULL, NULL);
    
    DefineCustomIntVariable("sql_firewall.select_limit_count", "Max SELECTs per window for per-command limit.", NULL, &select_limit_count, 0, 0, INT_MAX, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomIntVariable("sql_firewall.insert_limit_count", "Max INSERTs per window for per-command limit.", NULL, &insert_limit_count, 0, 0, INT_MAX, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomIntVariable("sql_firewall.update_limit_count", "Max UPDATEs per window for per-command limit.", NULL, &update_limit_count, 0, 0, INT_MAX, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomIntVariable("sql_firewall.delete_limit_count", "Max DELETEs per window for per-command limit.", NULL, &delete_limit_count, 0, 0, INT_MAX, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomIntVariable("sql_firewall.command_limit_seconds", "Time window in seconds for per-command rate limit.", NULL, &command_limit_seconds, 60, 0, INT_MAX, PGC_SUSET, 0, NULL, NULL, NULL);
    
    DefineCustomBoolVariable("sql_firewall.enable_application_blocking", "Enables blocking based on application_name.", NULL, &enable_application_blocking, false, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomStringVariable("sql_firewall.blocked_applications", "Comma-separated list of application_names to block.", NULL, &blocked_applications, "", PGC_SUSET, 0, NULL, NULL, NULL);
    
    DefineCustomBoolVariable("sql_firewall.enable_regex_scan", "Enables scanning queries against regex rules.", NULL, &enable_regex_scan, true, PGC_SUSET, 0, NULL, NULL, NULL);


    // Install the hooks into the query processing pipeline
    prev_executor_start_hook = ExecutorStart_hook;
    ExecutorStart_hook = sql_firewall_executor_start_hook;
    prev_process_utility_hook = ProcessUtility_hook;
    ProcessUtility_hook = sql_firewall_process_utility_hook;
}

/**
 * @brief Module finalization function (_PG_fini).
 * This function is called when the extension is unloaded.
 * It restores the original hooks to cleanly remove the firewall.
 */
void _PG_fini(void)
{
    // Uninstall the hooks, restoring the previous ones to ensure clean unload.
    ExecutorStart_hook = prev_executor_start_hook;
    ProcessUtility_hook = prev_process_utility_hook;
}
