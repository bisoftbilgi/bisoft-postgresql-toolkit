/*
 * SQL FIREWALL - PostgreSQL Extension
 */

#include <stdbool.h>
#include <ctype.h>
#include <string.h>     /* strlen, strcmp, strtok, strstr, strncpy */
#include <stdlib.h>     /* atoi */
#include "postgres.h"
#include "fmgr.h"
#include "access/xact.h"
#include "executor/spi.h"
#include "tcop/utility.h"
#include "executor/executor.h"
#include "utils/guc.h"
#include "utils/syscache.h"
#include "utils/builtins.h"
#include "utils/errcodes.h"
#include "parser/parse_node.h"
#include "nodes/parsenodes.h"
#include "utils/varlena.h"
#include "utils/datetime.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "libpq/libpq-be.h"
#include "libpq/auth.h"

/* External function prototypes from PostgreSQL backend */
extern bool superuser(void);
extern Oid GetUserId(void);
extern char *GetUserNameFromId(Oid roleid, bool noerror);

/* Required macro for a PostgreSQL extension */
PG_MODULE_MAGIC;

/* Forward declarations for module lifecycle functions */
void _PG_init(void);
void _PG_fini(void);

/* Pointers to save the previous hook functions, allowing us to chain calls */
static ExecutorStart_hook_type        prev_executor_start_hook  = NULL;
static ProcessUtility_hook_type       prev_process_utility_hook = NULL;
static ClientAuthentication_hook_type prev_client_auth_hook     = NULL;

/* --- Global Configuration Variables (GUCs) --- */

/* Firewall operational mode (learn, permissive, enforce) */
static int  sql_firewall_mode;
/* Re-entrancy guard to prevent recursive firewall checks */
static bool inside_firewall = false;
/* Enables scanning for blacklisted keywords */
static bool enable_keyword_scan;
/* Comma-separated list of keywords to block */
static char *blacklisted_keywords;
/* Enables quiet hours, blocking all non-superuser activity */
static bool enable_quiet_hours;
/* Start time for quiet hours (HH:MM) */
static char *quiet_hours_start;
/* End time for quiet hours (HH:MM) */
static char *quiet_hours_end;
/* Enables global query rate limiting */
static bool enable_rate_limiting;
/* Number of queries allowed per window for global rate limit */
static int  rate_limit_count;
/* Time window in seconds for global rate limit */
static int  rate_limit_seconds;
/* Enables scanning queries against regex rules in the database */
static bool enable_regex_scan;
/* Max SELECTs per window for per-command rate limit */
static int  select_limit_count;
/* Max INSERTs per window for per-command rate limit */
static int  insert_limit_count;
/* Max UPDATEs per window for per-command rate limit */
static int  update_limit_count;
/* Max DELETEs per window for per-command rate limit */
static int  delete_limit_count;
/* Time window in seconds for per-command rate limit */
static int  command_limit_seconds;
/* Enables blocking based on application_name */
static bool enable_application_blocking;
/* Comma-separated list of application_names to block */
static char *blocked_applications;
/* Enables blocking based on client IP address */
static bool enable_ip_blocking;
/* Comma-separated list of IP addresses to block */
static char *blocked_ips;
/* Enables role-to-IP binding, restricting roles to specific IPs */
static bool enable_role_ip_binding;
/* Comma-separated list of role@ip bindings */
static char *role_ip_bindings;

/* Enum for the different modes of the SQL firewall */
typedef enum {
    SQL_FIREWALL_MODE_LEARN,
    SQL_FIREWALL_MODE_PERMISSIVE,
    SQL_FIREWALL_MODE_ENFORCE
} SqlFirewallMode;

/* Options for the sql_firewall.mode GUC */
static const struct config_enum_entry mode_options[] = {
    {"learn",      SQL_FIREWALL_MODE_LEARN,      false},
    {"permissive", SQL_FIREWALL_MODE_PERMISSIVE, false},
    {"enforce",    SQL_FIREWALL_MODE_ENFORCE,    false},
    {NULL, 0, false}
};

/* ----------------------- Helper Functions ----------------------- */

/**
 * @brief Checks if a given role is allowed to connect from a specific IP address
 * based on the role_ip_bindings GUC.
 * @param role The connecting user's role name.
 * @param ip The connecting client's IP address.
 * @return true if the connection is allowed, false otherwise.
 * @note If no binding is defined for a specific role, it is allowed by this function.
 * The check is case-insensitive for role names.
 */
static bool is_role_ip_allowed_binding(const char *role, const char *ip)
{
    char *list_copy;
    char *tok;
    char *atpos;
    char *entry_role;
    char *entry_ip;
    bool has_any_binding_for_role = false;

    if (!enable_role_ip_binding || !role_ip_bindings || !*role_ip_bindings)
        return true; /* Feature is disabled or list is empty, so allow */

    if (!role || !*role)
        return true; /* Role is unknown (e.g., during early connection), allow */

    if (!ip || !*ip)
        return true; /* IP is unknown (e.g., local socket), allow */

    list_copy = pstrdup(role_ip_bindings);
    tok = strtok(list_copy, ",");

    while (tok)
    {
        /* Trim leading/trailing whitespace from token */
        while (*tok && isspace((unsigned char)*tok)) tok++;
        {
            char *end = tok + strlen(tok) - 1;
            while (end > tok && isspace((unsigned char)*end)) *end-- = '\0';
        }

        atpos = strchr(tok, '@');
        if (atpos && atpos > tok && *(atpos + 1))
        {
            *atpos = '\0'; /* Split the token into role and IP */
            entry_role = tok;
            entry_ip   = atpos + 1;

            if (pg_strcasecmp(role, entry_role) == 0)
            {
                has_any_binding_for_role = true;
                if (strcmp(ip, entry_ip) == 0)
                {
                    pfree(list_copy);
                    return true; /* Match found: this role is allowed from this IP */
                }
            }
        }

        tok = strtok(NULL, ",");
    }

    pfree(list_copy);

    if (has_any_binding_for_role)
        return false; /* A binding exists for this role, but the IP did not match */
    else
        return true;  /* No specific binding for this role, so allow */
}

/**
 * @brief Performs a case-insensitive, whole-word search for blacklisted keywords.
 * @param query_string The SQL query to scan.
 * @return The keyword that was found, or NULL if no keyword was found.
 * @note Checks for non-alphanumeric characters around the found keyword to
 * prevent false positives (e.g., blocking 'backdrop' because of 'drop').
 */
static const char* contains_blacklisted_keyword(const char *query_string)
{
    static char found[128];
    char *query_copy, *kw_copy, *token, *trimmed_token, *scan_ptr, *end, *p;

    if (!enable_keyword_scan || !blacklisted_keywords || !*blacklisted_keywords)
        return NULL;

    query_copy = pstrdup(query_string);
    for (p = query_copy; *p; ++p)
        *p = tolower((unsigned char)*p);

    kw_copy = pstrdup(blacklisted_keywords);
    token = strtok(kw_copy, ",");

    while (token)
    {
        trimmed_token = token;
        while (isspace((unsigned char)*trimmed_token)) trimmed_token++;
        end = trimmed_token + strlen(trimmed_token) - 1;
        while (end > trimmed_token && isspace((unsigned char)*end)) *end-- = '\0';

        for (p = trimmed_token; *p; ++p)
            *p = tolower((unsigned char)*p);

        scan_ptr = query_copy;
        while ((scan_ptr = strstr(scan_ptr, trimmed_token)) != NULL)
        {
            char char_before = (scan_ptr == query_copy) ? ' ' : *(scan_ptr - 1);
            char char_after = *(scan_ptr + strlen(trimmed_token));

            /* Check for word boundaries */
            if (!isalnum((unsigned char)char_before) && !isalnum((unsigned char)char_after))
            {
                strncpy(found, trimmed_token, sizeof(found) - 1);
                found[sizeof(found) - 1] = '\0';
                pfree(query_copy);
                pfree(kw_copy);
                return found;
            }
            scan_ptr++;
        }
        token = strtok(NULL, ",");
    }

    pfree(query_copy);
    pfree(kw_copy);
    return NULL;
}

/**
 * @brief Checks if the current server time is within the configured quiet hours.
 * @return true if it is quiet hours, false otherwise.
 * @note Optimized to use internal C functions for time, avoiding SPI overhead.
 */
static bool is_in_quiet_hours(void)
{
    int h = 0, m = 0, sh = 0, sm = 0, eh = 0, em = 0;
    int curr_mins = 0, start_mins = 0, end_mins = 0;
    TimestampTz now;
    struct pg_tm tm;
    fsec_t fsec;
    const char *tz_name;
    int tz;

    if (!enable_quiet_hours)
        return false;

    if (!quiet_hours_start || !quiet_hours_end ||
        quiet_hours_start[0] == '\0' || quiet_hours_end[0] == '\0')
        return false;

    if (sscanf(quiet_hours_start, "%d:%d", &sh, &sm) != 2 ||
        sscanf(quiet_hours_end, "%d:%d", &eh, &em) != 2)
        return false;

    now = GetCurrentTimestamp();

    if (timestamp2tm(now, &tz, &tm, &fsec, &tz_name, NULL) != 0)
        return false;  // timestamp dönüşümü başarısızsa sessizce reddet

    h = tm.tm_hour;
    m = tm.tm_min;

    curr_mins = h * 60 + m;
    start_mins = sh * 60 + sm;
    end_mins = eh * 60 + em;

    if (start_mins < end_mins)
        return (curr_mins >= start_mins && curr_mins < end_mins);
    else
        return (curr_mins >= start_mins || curr_mins < end_mins);
}



/**
 * @brief Checks if the current application name is in the block list.
 * @param current_app_name The application_name from the client connection.
 * @return The application name if found in the list, NULL otherwise.
 * @note Comparison is case-insensitive.
 */
static const char* is_application_blocked(const char* current_app_name)
{
    static char found_app[128];
    char *blocked_list_copy, *token, *end;

    if (!enable_application_blocking || !blocked_applications || !current_app_name ||
        !*blocked_applications || !*current_app_name)
        return NULL;

    blocked_list_copy = pstrdup(blocked_applications);
    token = strtok(blocked_list_copy, ",");

    while (token)
    {
        while (isspace((unsigned char)*token)) token++;
        end = token + strlen(token) - 1;
        while (end > token && isspace((unsigned char)*end)) *end-- = '\0';

        if (pg_strcasecmp(current_app_name, token) == 0)
        {
            strncpy(found_app, token, sizeof(found_app) - 1);
            found_app[sizeof(found_app) - 1] = '\0';
            pfree(blocked_list_copy);
            return found_app;
        }
        token = strtok(NULL, ",");
    }

    pfree(blocked_list_copy);
    return NULL;
}

/**
 * @brief Checks if the client IP is in the global block list.
 * @param client_ip The client's remote IP address.
 * @return The IP address if found in the list, NULL otherwise.
 */
static const char* is_ip_blocked(const char* client_ip)
{
    static char found_ip[128];
    char *blocked_list_copy, *token, *end;

    if (!enable_ip_blocking || !blocked_ips || !client_ip || !*blocked_ips)
        return NULL;

    blocked_list_copy = pstrdup(blocked_ips);
    token = strtok(blocked_list_copy, ",");

    while (token)
    {
        while (isspace((unsigned char)*token)) token++;
        end = token + strlen(token) - 1;
        while (end > token && isspace((unsigned char)*end)) *end-- = '\0';

        if (strcmp(client_ip, token) == 0)
        {
            strncpy(found_ip, token, sizeof(found_ip) - 1);
            found_ip[sizeof(found_ip) - 1] = '\0';
            pfree(blocked_list_copy);
            return found_ip;
        }
        token = strtok(NULL, ",");
    }

    pfree(blocked_list_copy);
    return NULL;
}

/**
 * @brief Retrieves the specific rate limit count for a given command type.
 * @param cmd The command type (e.g., "SELECT", "INSERT").
 * @return The configured limit count for that command, or 0 if none.
 */
static int get_command_limit(const char *cmd)
{
    if (strcmp(cmd, "SELECT") == 0) return select_limit_count;
    if (strcmp(cmd, "INSERT") == 0) return insert_limit_count;
    if (strcmp(cmd, "UPDATE") == 0) return update_limit_count;
    if (strcmp(cmd, "DELETE") == 0) return delete_limit_count;
    return 0;
}

/**
 * @brief Inserts a record into the firewall's activity log table via SPI.
 * @param role Current user role.
 * @param dbname Current database name.
 * @param action The action taken by the firewall (e.g., "BLOCKED", "ALLOWED").
 * @param reason The reason for the action.
 * @param query The full text of the query.
 * @param cmd_type The parsed command type (e.g., "SELECT").
 * @param spi_already_connected A boolean to avoid nested SPI connections.
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
    int ret;

    /* Null kontrolü */
    if (!role || !action || !query || !cmd_type)
        return;

    PG_TRY();
    {
        if (!spi_already_connected)
        {
            if (SPI_connect() != SPI_OK_CONNECT)
                elog(ERROR, "SPI_connect failed in log_firewall_action()");
            spi_started_here = true;
        }

        vals[0] = DirectFunctionCall1(namein, CStringGetDatum(role));
        vals[1] = DirectFunctionCall1(namein, CStringGetDatum(dbname ? dbname : "unknown"));
        vals[2] = CStringGetTextDatum(action);
        vals[3] = reason ? CStringGetTextDatum(reason) : (Datum) 0;
        vals[4] = CStringGetTextDatum(query);
        vals[5] = CStringGetTextDatum(cmd_type);

        if (!reason) nulls[3] = 'n';

        ret = SPI_execute_with_args(
            "INSERT INTO public.sql_firewall_activity_log (role_name, database_name, action, reason, query_text, command_type) "
            "VALUES ($1, $2, $3, $4, $5, $6)",
            6, types, vals, nulls, false, 0);

        /* SPI sonuçlarını temizle */
        if (ret == SPI_OK_INSERT && SPI_tuptable != NULL)
        {
            SPI_freetuptable(SPI_tuptable);
        }

        if (spi_started_here)
        {
            SPI_finish();
            spi_started_here = false;
        }
    }
    PG_CATCH();
    {
        /* Hata durumunda kaynakları temizle */
        if (spi_started_here)
        {
            SPI_finish();
        }
        
        /* Hataları bastır - log fonksiyonu ana işlemi engellememelidir */
        FlushErrorState();
        
        /* Opsiyonel: Hata durumunda warning log */
        elog(WARNING, "sql_firewall: Failed to log action to activity log");
    }
    PG_END_TRY();
}

/**
 * @brief Checks if the query matches any active regex block rules.
 * @param query_string The SQL query to check.
 * @param spi_already_connected A boolean to avoid nested SPI connections.
 * @return true if a match is found, false otherwise.
 * @note Optimized to use a single prepared SPI query for all rules.
 */
static bool query_matches_regex_block_rule(const char *query_string, bool spi_already_connected)
{
    bool match_found = false;
    bool spi_started_here = false;
    int ret;
    SPIPlanPtr plan = NULL;
    Datum q_datum;
    Oid q_type = TEXTOID;
    char q_null = ' ';

    if (!enable_regex_scan || !query_string)
        return false;

    PG_TRY();
    {
        if (!spi_already_connected)
        {
            if (SPI_connect() != SPI_OK_CONNECT)
                elog(ERROR, "SPI_connect failed in regex check");
            spi_started_here = true;
        }

        plan = SPI_prepare("SELECT EXISTS (SELECT 1 FROM public.sql_firewall_regex_rules "
                           "WHERE is_active = true AND action = 'BLOCK' AND $1 ~* pattern)",
                           1, &q_type);

        if (plan == NULL)
             elog(ERROR, "SPI_prepare failed for regex check");

        q_datum = CStringGetTextDatum(query_string);
        ret = SPI_execute_plan(plan, &q_datum, &q_null, true, 1);

        if (ret == SPI_OK_SELECT && SPI_processed > 0 && SPI_tuptable != NULL)
        {
            bool is_null;
            Datum match_datum = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &is_null);
            if (!is_null)
                match_found = DatumGetBool(match_datum);
            
            /* Tuptable'ı temizle */
            SPI_freetuptable(SPI_tuptable);
        }

        /* Plan'ı serbest bırak */
        if (plan != NULL)
        {
            SPI_freeplan(plan);
            plan = NULL;
        }

        if (spi_started_here)
        {
            SPI_finish();
            spi_started_here = false;
        }
    }
    PG_CATCH();
    {
        /* Hata durumunda kaynakları temizle */
        if (plan != NULL)
        {
            SPI_freeplan(plan);
        }
        
        if (spi_started_here)
        {
            SPI_finish();
        }
        
        FlushErrorState();
        return false;
    }
    PG_END_TRY();

    return match_found;
}

/* ----------------------- Firewall Core ----------------------- */

/* ----------------------- Firewall Core ----------------------- */

/**
 * @brief The main firewall logic function, called by the query hooks.
 * It performs all checks in a specific order for robustness.
 * Checks that do not require an SPI connection are performed first.
 */
static void check_firewall(const char *query)
{
    const char *cmd = "OTHER";
    const char *kw = NULL;
    char *role = NULL;
    char *db_name = NULL;
    bool spi_started = false;

    /* Prevent recursive calls to the firewall from within itself */
    if (inside_firewall) return;
    inside_firewall = true;

    /* Superusers are always exempt from firewall checks */
    if (superuser()) {
        inside_firewall = false;
        return;
    }

    role = GetUserNameFromId(GetUserId(), false);
    if (!role) { /* Should not happen in normal operation */
        inside_firewall = false;
        return;
    }

    /*
     * ====================================================================
     * STAGE 1: Checks NOT requiring an SPI connection.
     * These are checked first to avoid opening a DB connection unless
     * absolutely necessary. This makes error handling simpler and safer.
     * ====================================================================
     */

    if (is_in_quiet_hours())
{
    inside_firewall = false;

    // Çökme engelleyici NULL kontrolleri
    if (quiet_hours_start && quiet_hours_end)
    {
        ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                        errmsg("sql_firewall: Blocked during quiet hours (%s - %s).",
                               quiet_hours_start, quiet_hours_end)));
    }
    else
    {
        ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                        errmsg("sql_firewall: Blocked during quiet hours (invalid time config).")));
    }

    return;
}



    kw = contains_blacklisted_keyword(query);
    if (kw)
    {
        /* Same as above: report error before connecting to SPI */
        inside_firewall = false; /* Release re-entrancy guard */
        ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR_OR_ACCESS_RULE_VIOLATION),
                        errmsg("sql_firewall: Blocked due to blacklisted keyword '%s'.", kw)));
        return; /* Should not be reached */
    }


    /*
     * ====================================================================
     * STAGE 2: Checks that DO require an SPI connection.
     * All subsequent operations are wrapped in a PG_TRY block to safely
     * manage the SPI connection state in case of errors.
     * ====================================================================
     */

    PG_TRY();
    {
        List *tree = NULL;

        /* Establish connection to the database for running checks */
        if (SPI_connect() != SPI_OK_CONNECT)
            elog(ERROR, "SPI_connect failed in check_firewall");
        spi_started = true;

        if (SPI_execute("SELECT current_database()", true, 1) == SPI_OK_SELECT && SPI_processed > 0)
            db_name = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);

        /* Parse the query to determine its type (SELECT, INSERT, etc.) */
        tree = pg_parse_query(query);
        if (tree && list_length(tree) == 1)
        {
            RawStmt *stmt = linitial_node(RawStmt, tree);
            if (IsA(stmt->stmt, InsertStmt)) cmd = "INSERT";
            else if (IsA(stmt->stmt, UpdateStmt)) cmd = "UPDATE";
            else if (IsA(stmt->stmt, DeleteStmt)) cmd = "DELETE";
            else if (IsA(stmt->stmt, SelectStmt)) cmd = "SELECT";
        }
        if (tree)
            list_free_deep(tree); /* Avoid memory leak */

        /* --- STAGE 2A: Regex Check --- */
        if (query_matches_regex_block_rule(query, true))
        {
            log_firewall_action(role, db_name, "BLOCKED", "Regex pattern match", query, cmd, true);
            ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                            errmsg("sql_firewall: Query blocked by security regex pattern.")));
        }

        /* --- STAGE 2B: Rate Limiting --- */
        if (enable_rate_limiting)
        {
            int query_count = 0;
            char *ratelimit_sql = psprintf(
                "SELECT COUNT(*) FROM public.sql_firewall_activity_log "
                "WHERE role_name = %s AND log_time > now() - interval '%d seconds' AND action <> 'LEARNED (Command)'",
                quote_literal_cstr(role), rate_limit_seconds);

            if (SPI_execute(ratelimit_sql, true, 1) == SPI_OK_SELECT && SPI_processed > 0)
            {
                char *count_str = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
                if (count_str) { query_count = atoi(count_str); pfree(count_str); }
            }
            pfree(ratelimit_sql);

            if (query_count >= rate_limit_count)
            {
                char *reason = psprintf("Rate limit exceeded: %d/%d queries in %d seconds",
                                        query_count + 1, rate_limit_count, rate_limit_seconds);
                log_firewall_action(role, db_name, "BLOCKED", reason, query, cmd, true);
                pfree(reason);
                ereport(ERROR, (errcode(ERRCODE_CONFIGURATION_LIMIT_EXCEEDED),
                                errmsg("sql_firewall: Rate limit exceeded for role '%s'.", role)));
            }
        }

        if (command_limit_seconds > 0)
        {
            int command_limit = get_command_limit(cmd);
            if (command_limit > 0)
            {
                int cmd_count = 0;
                char *cmd_sql = psprintf(
                    "SELECT COUNT(*) FROM public.sql_firewall_activity_log "
                    "WHERE role_name = %s AND command_type = %s "
                    "AND log_time > now() - interval '%d seconds'",
                    quote_literal_cstr(role), quote_literal_cstr(cmd), command_limit_seconds);

                if (SPI_execute(cmd_sql, true, 1) == SPI_OK_SELECT && SPI_processed > 0)
                {
                    char *count_str = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
                    if (count_str) { cmd_count = atoi(count_str); pfree(count_str); }
                }
                pfree(cmd_sql);

                if (cmd_count >= command_limit)
                {
                    char *reason = psprintf("%s limit exceeded: %d/%d in %d seconds",
                                            cmd, cmd_count + 1, command_limit, command_limit_seconds);
                    log_firewall_action(role, db_name, "BLOCKED", reason, query, cmd, true);
                    pfree(reason);
                    ereport(ERROR, (errcode(ERRCODE_CONFIGURATION_LIMIT_EXCEEDED),
                                    errmsg("sql_firewall: Rate limit for command '%s' exceeded for role '%s'", cmd, role)));
                }
            }
        }

        /* --- STAGE 2C: Main Rule Engine (Learn/Permissive/Enforce) --- */
        if (strcmp(cmd, "OTHER") != 0)
        {
            char *rule_sql = psprintf("SELECT is_approved FROM public.sql_firewall_command_approvals "
                                      "WHERE role_name = %s AND command_type = %s",
                                      quote_literal_cstr(role), quote_literal_cstr(cmd));
            int ret = SPI_execute(rule_sql, true, 1);
            pfree(rule_sql);

            if (ret == SPI_OK_SELECT && SPI_processed > 0) /* Rule found */
            {
                bool is_null;
                bool is_approved = DatumGetBool(SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &is_null));
                if (is_null) is_approved = false;

                if (is_approved) {
                    log_firewall_action(role, db_name, "ALLOWED", "Approved command type", query, cmd, true);
                } else { /* Rule exists but is not approved */
                    if (sql_firewall_mode == SQL_FIREWALL_MODE_PERMISSIVE) {
                        log_firewall_action(role, db_name, "ALLOWED (PERMISSIVE)", "Command type approval pending", query, cmd, true);
                    } else { /* Enforce or Learn mode */
                        log_firewall_action(role, db_name, "BLOCKED", "Command type approval pending", query, cmd, true);
                        ereport(ERROR, (errmsg("sql_firewall: Approval for command '%s' is pending for role '%s'", cmd, role)));
                    }
                }
            }
            else /* No rule found for this role/command combination */
            {
                if (sql_firewall_mode == SQL_FIREWALL_MODE_LEARN)
                {
                    Datum insert_vals[2];
                    Oid   insert_types[2] = {NAMEOID, TEXTOID};
                    char  insert_nulls[3] = {' ', ' ', '\0'};

                    insert_vals[0] = DirectFunctionCall1(namein, CStringGetDatum(role));
                    insert_vals[1] = CStringGetTextDatum(cmd);

                    SPI_execute_with_args(
                        "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type) "
                        "VALUES ($1, $2) ON CONFLICT DO NOTHING",
                        2, insert_types, insert_vals, insert_nulls, false, 0);
                    log_firewall_action(role, db_name, "LEARNED (Command)", "New command type detected", query, cmd, true);
                }
                else if (sql_firewall_mode == SQL_FIREWALL_MODE_PERMISSIVE)
                {
                    log_firewall_action(role, db_name, "ALLOWED (PERMISSIVE)", "No rule for command type", query, cmd, true);
                }
                else /* ENFORCE mode */
                {
                    log_firewall_action(role, db_name, "BLOCKED", "No rule for command type", query, cmd, true);
                    ereport(ERROR, (errmsg("sql_firewall: No rule found for command '%s' for role '%s'", cmd, role)));
                }
            }
        }
        else /* Command type is not one we track (e.g., SET, VACUUM), so allow */
        {
             log_firewall_action(role, db_name, "ALLOWED", "Command type is 'OTHER'", query, cmd, true);
        }

        /* --- Cleanup --- */
	SPI_finish();
        if (db_name)
            pfree(db_name);
        inside_firewall = false;
    }
    PG_CATCH();
    {
        /* Ensure resources are released in case of an error */
        if (db_name)
            pfree(db_name);
        if (spi_started)
            SPI_finish();
        inside_firewall = false;
        PG_RE_THROW(); /* Re-throw the original error */
    }
    PG_END_TRY();
}

/* ----------------------- Hook Wrappers ----------------------- */

/**
 * @brief Hook for ExecutorStart. This hook is responsible for checking DML
 * commands like SELECT, INSERT, UPDATE, DELETE.
 */
static void sql_firewall_executor_start_hook(QueryDesc *queryDesc, int eflags)
{
    /* Only check planned DML, not utility commands, to prevent double checks. */
    if (queryDesc->plannedstmt && queryDesc->plannedstmt->commandType != CMD_UTILITY)
    {
        check_firewall(queryDesc->sourceText);
    }

    /* Chain to the previous hook or standard function */
    if (prev_executor_start_hook)
        prev_executor_start_hook(queryDesc, eflags);
    else
        standard_ExecutorStart(queryDesc, eflags);
}

/**
 * @brief Hook for ProcessUtility. This hook is responsible for checking Utility
 * commands like CREATE, ALTER, DROP, VACUUM, etc.
 */
static void sql_firewall_process_utility_hook(PlannedStmt *pstmt, const char *queryString,
                                              bool readOnlyTree, ProcessUtilityContext context,
                                              ParamListInfo params, QueryEnvironment *queryEnv,
                                              DestReceiver *dest, QueryCompletion *qc)
{
    /* Explicitly check for utility commands for safety and clarity */
    if (pstmt && pstmt->commandType == CMD_UTILITY)
        check_firewall(queryString);

    /* Chain to the previous hook or standard function */
    if (prev_process_utility_hook)
        prev_process_utility_hook(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
    else
        standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
}

/* ----------------------- Client Authentication Hook ----------------------- */

/**
 * @brief Hook for ClientAuthentication. This runs very early in the connection
 * process and is used to block connections entirely based on IP,
 * application name, or role-IP bindings.
 */
static void sql_firewall_client_auth_hook(Port *port, int status)
{
    if (port)
    {
        const char *addr = (port->remote_host && port->remote_host[0]) ? port->remote_host : NULL;
        const char *app  = port->application_name;
        const char *user = port->user_name; // Kullanıcı adını port'tan alıyoruz

        /* --- IP Adresine Göre Engelleme --- */
        if (addr && is_ip_blocked(addr))
        {
            ereport(FATAL,
                    (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
                     errmsg("sql_firewall: Connection from blocked IP address '%s' is not allowed.", addr)));
        }

        /* --- Uygulama Adına Göre Engelleme --- */
        if (app && is_application_blocked(app))
        {
            ereport(FATAL,
                    (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
                     errmsg("sql_firewall: Connections from application '%s' are not allowed.", app)));
        }

        if (user && addr && !is_role_ip_allowed_binding(user, addr))
        {
            ereport(FATAL,
                    (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
                     errmsg("sql_firewall: Role '%s' is not allowed to connect from IP address '%s'.", user, addr)));
        }
    }

    if (prev_client_auth_hook)
        prev_client_auth_hook(port, status);
}

/* ----------------------- Module Init / Fini ----------------------- */

/**
 * @brief Module initialization function.
 * This function is called when the extension is loaded. It defines all GUCs
 * and installs the necessary hooks.
 */
void _PG_init(void)
{
    /* Define all our GUCs (Grand Unified Configuration variables) */
    DefineCustomEnumVariable("sql_firewall.mode", "Sets the firewall operation mode.", NULL, &sql_firewall_mode, SQL_FIREWALL_MODE_LEARN, mode_options, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomBoolVariable("sql_firewall.enable_keyword_scan", "Enables scanning for blacklisted keywords.", NULL, &enable_keyword_scan, false, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomStringVariable("sql_firewall.blacklisted_keywords", "Comma-separated list of keywords to block.", NULL, &blacklisted_keywords, "drop,truncate", PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomBoolVariable("sql_firewall.enable_quiet_hours", "Enables quiet hours.", NULL, &enable_quiet_hours, false, PGC_SUSET, 0, NULL, NULL, NULL);
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
    DefineCustomBoolVariable("sql_firewall.enable_ip_blocking", "Enables blocking based on client IP address.", NULL, &enable_ip_blocking, false, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomStringVariable("sql_firewall.blocked_ips", "Comma-separated list of IP addresses to block.", NULL, &blocked_ips, "", PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomBoolVariable("sql_firewall.enable_role_ip_binding", "If on, restricts roles to specific IPs defined in role_ip_bindings.", NULL, &enable_role_ip_binding, false, PGC_SUSET, 0, NULL, NULL, NULL);
    DefineCustomStringVariable("sql_firewall.role_ip_bindings", "Comma-separated list like: role1@10.0.0.5,role2@192.168.1.100", NULL, &role_ip_bindings, "", PGC_SUSET, 0, NULL, NULL, NULL);

    /* Install all hooks */
    prev_executor_start_hook = ExecutorStart_hook;
    ExecutorStart_hook = sql_firewall_executor_start_hook;
    prev_process_utility_hook = ProcessUtility_hook;
    ProcessUtility_hook = sql_firewall_process_utility_hook;
    prev_client_auth_hook = ClientAuthentication_hook;
    ClientAuthentication_hook = sql_firewall_client_auth_hook;
}

/**
 * @brief Module finalization function.
 * This function is called when the extension is unloaded. It uninstalls all
 * hooks to restore the system to its previous state.
 */
void _PG_fini(void)
{
    /* Uninstall all hooks */
    ExecutorStart_hook        = prev_executor_start_hook;
    ProcessUtility_hook       = prev_process_utility_hook;
    ClientAuthentication_hook = prev_client_auth_hook;
}

/* ----------------------- SQL-Callable Functions ----------------------- */

/**
 * @brief SQL-callable function to reset (delete) the activity log for a given role.
 * Requires superuser privileges.
 */
PG_FUNCTION_INFO_V1(sql_firewall_reset_log_for_role);
Datum
sql_firewall_reset_log_for_role(PG_FUNCTION_ARGS)
{
    Name role_to_reset = PG_GETARG_NAME(0);
    char *sql;
    long processed;

    if (!superuser())
        ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                        errmsg("Only superusers can call sql_firewall_reset_log_for_role()")));

    if (SPI_connect() != SPI_OK_CONNECT)
        elog(ERROR, "SPI_connect failed in sql_firewall_reset_log_for_role");

    sql = psprintf("DELETE FROM public.sql_firewall_activity_log WHERE role_name = %s",
                   quote_literal_cstr(NameStr(*role_to_reset)));

    SPI_execute(sql, false, 0);
    processed = SPI_processed;
    pfree(sql);
    SPI_finish();

    PG_RETURN_INT64(processed);
}

/**
 * @brief SQL-callable function to approve all pending commands for a given role.
 * Requires superuser privileges.
 */
PG_FUNCTION_INFO_V1(sql_firewall_approve_all_for_role);
Datum
sql_firewall_approve_all_for_role(PG_FUNCTION_ARGS)
{
    Name role_to_approve = PG_GETARG_NAME(0);
    char *sql;
    long processed;

    if (!superuser())
        ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                        errmsg("Only superusers can call this function.")));

    if (SPI_connect() != SPI_OK_CONNECT)
        elog(ERROR, "SPI_connect failed in sql_firewall_approve_all_for_role");

    sql = psprintf("UPDATE public.sql_firewall_command_approvals SET is_approved = true "
                   "WHERE role_name = %s AND is_approved = false",
                   quote_literal_cstr(NameStr(*role_to_approve)));

    SPI_execute(sql, false, 0);
    processed = SPI_processed;
    pfree(sql);
    SPI_finish();

    PG_RETURN_INT64(processed);
}

/**
 * @brief SQL-callable function to reject (un-approve) all approved commands for a given role.
 * Requires superuser privileges.
 */
PG_FUNCTION_INFO_V1(sql_firewall_reject_all_for_role);
Datum
sql_firewall_reject_all_for_role(PG_FUNCTION_ARGS)
{
    Name role_to_reject = PG_GETARG_NAME(0);
    char *sql;
    long processed;

    if (!superuser())
        ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                        errmsg("Only superusers can call this function.")));

    if (SPI_connect() != SPI_OK_CONNECT)
        elog(ERROR, "SPI_connect failed in sql_firewall_reject_all_for_role");

    sql = psprintf("UPDATE public.sql_firewall_command_approvals SET is_approved = false "
                   "WHERE role_name = %s AND is_approved = true",
                   quote_literal_cstr(NameStr(*role_to_reject)));

    SPI_execute(sql, false, 0);
    processed = SPI_processed;
    pfree(sql);
    SPI_finish();

    PG_RETURN_INT64(processed);
}
