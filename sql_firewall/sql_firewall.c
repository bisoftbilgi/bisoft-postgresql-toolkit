/*
 * SQL FIREWALL - FINAL PROJECT CODE
 * Compiler warnings have been resolved.
 * MODIFIED TO USE COMMAND-BASED APPROVAL LOGIC.
 * FINAL FIX for transaction rollback issue in LEARN mode.
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
    SQL_FIREWALL_MODE_LEARN,      // Learn new command types and add them to the ruleset
    SQL_FIREWALL_MODE_PERMISSIVE, // Log but allow unapproved command types
    SQL_FIREWALL_MODE_ENFORCE     // Block unapproved command types
} SqlFirewallMode;

// Options for the sql_firewall.mode GUC, displayed in pg_settings
static const struct config_enum_entry mode_options[] = {
    {"learn", SQL_FIREWALL_MODE_LEARN, false},
    {"permissive", SQL_FIREWALL_MODE_PERMISSIVE, false},
    {"enforce", SQL_FIREWALL_MODE_ENFORCE, false},
    {NULL, 0, false}
};


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

    copy = pstrdup(query_string);
    for (i = 0; copy[i]; i++)
        copy[i] = tolower(copy[i]);

    kw = pstrdup(blacklisted_keywords);
    token = strtok(kw, ",");

    while (token)
    {
        while (isspace((unsigned char)*token)) token++;
        end = token + strlen(token) - 1;
        while (end > token && isspace((unsigned char)*end)) *end-- = '\0';

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
static bool is_in_quiet_hours(bool spi_already_connected)
{
    bool result = false;
    int h = 0, m = 0, sh = 0, sm = 0, eh = 0, em = 0;
    char *time_str = NULL;
    int curr = 0, start = 0, end = 0;
    bool spi_started_here = false;

    if (!enable_quiet_hours)
        return false;

    PG_TRY();
    {
        if (!spi_already_connected)
        {
            if (SPI_connect() != SPI_OK_CONNECT)
                elog(ERROR, "SPI_connect failed in is_in_quiet_hours()");
            spi_started_here = true;
        }

        if (SPI_execute("SELECT to_char(now(), 'HH24:MI')", true, 0) == SPI_OK_SELECT && SPI_processed > 0)
        {
            time_str = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
            if (time_str)
            {
                sscanf(time_str, "%d:%d", &h, &m);
                sscanf(quiet_hours_start, "%d:%d", &sh, &sm);
                sscanf(quiet_hours_end, "%d:%d", &eh, &em);
                curr = h * 60 + m;
                start = sh * 60 + sm;
                end = eh * 60 + em;
                result = (start < end) ? (curr >= start && curr < end)
                                       : (curr >= start || curr < end);
            }
        }

        if (spi_started_here)
            SPI_finish();
    }
    PG_CATCH();
    {
        if (spi_started_here)
            SPI_finish();
        FlushErrorState();
        result = false;
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

    blocked_list_copy = pstrdup(blocked_applications);
    token = strtok(blocked_list_copy, ",");

    while (token)
    {
        while (isspace((unsigned char)*token)) token++;
        end = token + strlen(token) - 1;
        while (end > token && isspace((unsigned char)*end)) *end-- = '\0';

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
    return 0;
}

/**
 * @brief Logs firewall activity to the sql_firewall_activity_log table.
 * @param role The user role performing the action.
 * @param action The action taken by the firewall (e.g., "ALLOWED", "BLOCKED", "LEARNED").
 * @param reason The reason for the action.
 * @param query The full text of the SQL query.
 * @param cmd_type The type of the SQL command (e.g., "SELECT", "UPDATE").
 */
static void log_firewall_action(const char *role, const char *dbname,
                                const char *action, const char *reason,
                                const char *query, const char *cmd_type,
                                bool spi_already_connected)

{
    Datum vals[6];
    Oid types[6] = {NAMEOID, NAMEOID, TEXTOID, TEXTOID, TEXTOID, TEXTOID};
    char nulls[7] = {' ', ' ', ' ', ' ', ' ', ' ', '\0'};
    bool spi_started_here = false;

    PG_TRY();
    {
        if (!spi_already_connected)
        {
            if (SPI_connect() != SPI_OK_CONNECT)
                elog(ERROR, "SPI_connect failed in log_firewall_action()");
            spi_started_here = true;
        }

        vals[0] = CStringGetDatum(role);
        vals[1] = CStringGetDatum(dbname ? dbname : "unknown");
        vals[2] = CStringGetTextDatum(action);
        vals[3] = reason ? CStringGetTextDatum(reason) : (Datum) 0;
        vals[4] = CStringGetTextDatum(query);
        vals[5] = CStringGetTextDatum(cmd_type);

        if (!reason) nulls[3] = 'n';

        SPI_execute_with_args(
            "INSERT INTO sql_firewall_activity_log (role_name, database_name, action, reason, query_text, command_type) "
            "VALUES ($1, $2, $3, $4, $5, $6)",
            6, types, vals, nulls, false, 0);

        if (spi_started_here)
            SPI_finish();
    }
    PG_CATCH();
    {
        if (spi_started_here)
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
static bool query_matches_regex_block_rule(const char *query_string, bool spi_already_connected)
{
    bool match_found = false;
    char *sql_get_patterns;
    bool spi_started_here = false;
    int ret, i;

    if (!enable_regex_scan)
        return false;

    PG_TRY();
    {
        if (!spi_already_connected)
        {
            if (SPI_connect() != SPI_OK_CONNECT)
                elog(ERROR, "SPI_connect failed in regex check");
            spi_started_here = true;
        }

        sql_get_patterns = "SELECT pattern FROM sql_firewall_regex_rules WHERE is_active = true AND action = 'BLOCK'";
        ret = SPI_execute(sql_get_patterns, true, 0);

        if (ret != SPI_OK_SELECT)
            elog(ERROR, "SPI_execute failed to get regex rules");

        for (i = 0; i < SPI_processed; i++)
        {
            char *pattern;
            Datum match_datum;
            bool is_null;
            char *check_sql;

            pattern = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1);

            if (pattern)
            {
                check_sql = psprintf("SELECT %s ~* %s", quote_literal_cstr(query_string), quote_literal_cstr(pattern));
                ret = SPI_execute(check_sql, true, 1);
                pfree(check_sql);

                if (ret == SPI_OK_SELECT && SPI_processed > 0)
                {
                    match_datum = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &is_null);
                    if (!is_null && DatumGetBool(match_datum))
                    {
                        match_found = true;
                        pfree(pattern);
                        break;
                    }
                }
                pfree(pattern);
            }
        }

        if (spi_started_here)
            SPI_finish();
    }
    PG_CATCH();
    {
        if (spi_started_here)
            SPI_finish();
        FlushErrorState();
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
    bool spi_started = false;
    int ret;
    const char *kw;
    char *db_name = NULL;
    const char *current_app_name = NULL;
    const char *blocked_app = NULL;
    char *cmd_sql = NULL;

    if (inside_firewall) return;
    inside_firewall = true;

    if (superuser()) {
        inside_firewall = false;
        return;
    }

    PG_TRY();
    {
        if (SPI_connect() != SPI_OK_CONNECT)
            elog(ERROR, "SPI_connect failed");
        spi_started = true;

        if (SPI_execute("SELECT current_database()", true, 1) == SPI_OK_SELECT && SPI_processed > 0)
            db_name = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);

        if (query_matches_regex_block_rule(query, true))
        {
            log_firewall_action(role, db_name, "BLOCKED", "Regex pattern match", query, "UNKNOWN", true);
            ereport(ERROR,
                    (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                     errmsg("sql_firewall: Query blocked due to matching a security regex pattern.")));
        }

        tree = pg_parse_query(query);
        if (tree && list_length(tree) == 1)
        {
            RawStmt *stmt = linitial_node(RawStmt, tree);
            if (IsA(stmt->stmt, InsertStmt)) cmd = "INSERT";
            else if (IsA(stmt->stmt, UpdateStmt)) cmd = "UPDATE";
            else if (IsA(stmt->stmt, DeleteStmt)) cmd = "DELETE";
            else if (IsA(stmt->stmt, SelectStmt)) cmd = "SELECT";
        }

        if (enable_application_blocking)
        {
            current_app_name = GetConfigOptionByName("application_name", NULL, false);
            blocked_app = is_application_blocked(current_app_name);
            if (blocked_app)
            {
                log_firewall_action(role, db_name, "BLOCKED", "Blocked application", query, cmd, true);
                ereport(ERROR,
                    (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                     errmsg("sql_firewall: Connections from application '%s' are not allowed.", blocked_app)));
            }
        }
        if (enable_rate_limiting)
        {
            int query_count = 0;
            char *ratelimit_sql = psprintf(
                "SELECT COUNT(*) FROM sql_firewall_activity_log "
                "WHERE role_name = '%s' AND log_time > now() - interval '%d seconds' AND action <> 'LEARNED (Command)'",
                role, rate_limit_seconds);

            if (SPI_execute(ratelimit_sql, true, 1) == SPI_OK_SELECT && SPI_processed > 0)
            {
                char *count_str = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
                if (count_str) query_count = atoi(count_str);
            }
            pfree(ratelimit_sql);

            if (query_count >= rate_limit_count)
            {
                 log_firewall_action(role, db_name, "BLOCKED", "Rate limit exceeded", query, cmd, true);
                 ereport(ERROR, (errmsg("sql_firewall: Rate limit exceeded for role '%s'.", role)));
            }
        }

        if (command_limit_seconds > 0)
        {
            int command_limit = get_command_limit(cmd);
            int cmd_count = 0;

            if (command_limit > 0)
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

                if (cmd_count >= command_limit)
                {
                    log_firewall_action(role, db_name, "BLOCKED", "Per-command rate limit exceeded", query, cmd, true);
                    ereport(ERROR, (errmsg("sql_firewall: Rate limit for command '%s' exceeded for role '%s'", cmd, role)));
                }
            }
        }

        if (is_in_quiet_hours(true))
        {
            log_firewall_action(role, db_name, "BLOCKED", "Quiet hours", query, cmd, true);
            ereport(ERROR, (errmsg("sql_firewall: Blocked during quiet hours")));
        }

        kw = contains_blacklisted_keyword(query);
        if (kw)
        {
            log_firewall_action(role, db_name, "BLOCKED", kw, query, cmd, true);
            ereport(ERROR, (errmsg("sql_firewall: Blocked due to keyword '%s'", kw)));
        }

        // =========================================================================
        // === YENİ MANTIK: Komut Bazlı Onay Kontrolü                              ===
        // =========================================================================

        if (strcmp(cmd, "OTHER") != 0)
        {
            char *rule_sql = psprintf("SELECT is_approved FROM sql_firewall_command_approvals "
                                      "WHERE role_name = %s AND command_type = %s",
                                      quote_literal_cstr(role), quote_literal_cstr(cmd));
            ret = SPI_execute(rule_sql, true, 1);
            pfree(rule_sql);

            if (ret == SPI_OK_SELECT && SPI_processed > 0)
            {
                // Kural bulundu
                bool is_null;
                bool is_approved = DatumGetBool(SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &is_null));
                if (is_null) is_approved = false;

                if (is_approved)
                {
                    log_firewall_action(role, db_name, "ALLOWED", "Approved command type", query, cmd, true);
                }
                else
                {
                    if (sql_firewall_mode == SQL_FIREWALL_MODE_PERMISSIVE)
                    {
                        log_firewall_action(role, db_name, "ALLOWED (PERMISSIVE)", "Command type approval pending", query, cmd, true);
                    }
                    else
                    {
                        log_firewall_action(role, db_name, "BLOCKED", "Command type approval pending", query, cmd, true);
                        ereport(ERROR, (errmsg("sql_firewall: Approval for command '%s' is pending for role '%s'", cmd, role)));
                    }
                }
            }
            else // Kural bulunamadı
            {
                if (sql_firewall_mode == SQL_FIREWALL_MODE_LEARN)
                {
                    Datum insert_vals[2];
                    Oid insert_types[2] = {NAMEOID, TEXTOID};
                    char insert_nulls[3] = {' ', ' ', '\0'};

                    insert_vals[0] = CStringGetDatum(role);
                    insert_vals[1] = CStringGetTextDatum(cmd);

                    SPI_execute_with_args("INSERT INTO sql_firewall_command_approvals (role_name, command_type) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                                          2, insert_types, insert_vals, insert_nulls, false, 0);

                    log_firewall_action(role, db_name, "LEARNED (Command)", "New command type detected", query, cmd, true);
                    // DÜZELTME: HATA VERMEK YERİNE SORGUNUN ÇALIŞMASINA İZİN VER. BU, INSERT'in geri alınmasını (rollback) engeller.
                }
                else if (sql_firewall_mode == SQL_FIREWALL_MODE_PERMISSIVE)
                {
                     log_firewall_action(role, db_name, "ALLOWED (PERMISSIVE)", "No rule for command type", query, cmd, true);
                }
                else // ENFORCE
                {
                    log_firewall_action(role, db_name, "BLOCKED", "No rule for command type", query, cmd, true);
                    ereport(ERROR, (errmsg("sql_firewall: No rule found for command '%s' for role '%s'", cmd, role)));
                }
            }
        }
        else
        {
             log_firewall_action(role, db_name, "ALLOWED", "Command type is 'OTHER'", query, cmd, true);
        }

        SPI_finish();
        inside_firewall = false;
    }
    PG_CATCH();
    {
        if (spi_started)
            SPI_finish();
        inside_firewall = false;
        PG_RE_THROW();
    }
    PG_END_TRY();
}


/**
 * @brief ExecutorStart hook function.
 * This hook is called for DML queries (SELECT, INSERT, UPDATE, DELETE).
 * It calls the main firewall check function.
 */
static void sql_firewall_executor_start_hook(QueryDesc *queryDesc, int eflags)
{
    check_firewall(queryDesc->sourceText);
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
    check_firewall(queryString);
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
    ExecutorStart_hook = prev_executor_start_hook;
    ProcessUtility_hook = prev_process_utility_hook;
}
