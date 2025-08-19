/*
 * SQL FIREWALL - PostgreSQL Extension (PG16-safe final version)
 *
 * Highlights:
 * - Skips internal/maintenance commands (SET/SHOW/pg_reload_conf/etc.)
 * - Correct GUC hook signatures for PostgreSQL 16 (check/assign hooks)
 * - Guards for NULL sourceText and non-transaction states
 * - No SPI unless IsTransactionState() is true
 * - Consistent cleanup of SPI resources (tuptable/plan)
 * - Optional superuser ('postgres') bypass at ClientAuthentication stage
 * - Quiet-hours values validated (HH:MM) via check hooks
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
#include "nodes/pg_list.h"
#include "parser/parser.h"
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

/* Previous hooks (chain responsibly) */
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
/* Max per-command limits */
static int  select_limit_count;
static int  insert_limit_count;
static int  update_limit_count;
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

/* Optional safety GUCs */
static bool skip_internal_commands = true;       /* skip SET/SHOW/etc. in hooks */
static bool allow_superuser_bypass_auth = true;  /* don't block 'postgres' at ClientAuthentication */

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

/* ---- Prototypes ---- */
static void validate_hhmm_or_error(const char *val, const char *gucname);
static bool check_quiet_hours_start(char **newval, void **extra, GucSource source);
static void assign_quiet_hours_start(const char *newval, void *extra);
static bool check_quiet_hours_end(char **newval, void **extra, GucSource source);
static void assign_quiet_hours_end(const char *newval, void *extra);
static bool is_role_ip_allowed_binding(const char *role, const char *ip);
static const char* contains_blacklisted_keyword(const char *query_string);
static bool is_in_quiet_hours(void);
static const char* is_application_blocked(const char* current_app_name);
static const char* is_ip_blocked(const char* client_ip);
static int  get_command_limit(const char *cmd);
static void log_firewall_action(const char *role, const char *dbname,
                                const char *action, const char *reason,
                                const char *query, const char *cmd_type,
                                bool spi_already_connected);
static bool query_matches_regex_block_rule(const char *query_string, bool spi_already_connected);
static bool should_skip_command(const char *q);
static void check_firewall(const char *query);

/* ----------------------- Helper Functions ----------------------- */

/* Validate "HH:MM" (00..23:00..59). Throws ERROR on invalid. */
static void validate_hhmm_or_error(const char *val, const char *gucname)
{
    int h, m;
    if (!val || sscanf(val, "%d:%d", &h, &m) != 2 || h < 0 || h > 23 || m < 0 || m > 59)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("invalid %s value '%s' (expected HH:MM)", gucname, val ? val : "(null)")));
}

/* GUC hooks (PG16 signatures) */
static bool check_quiet_hours_start(char **newval, void **extra, GucSource source)
{
    if (newval && *newval && **newval)
        validate_hhmm_or_error(*newval, "sql_firewall.quiet_hours_start");
    return true; /* accept the value */
}
static void assign_quiet_hours_start(const char *newval, void *extra)
{
    /* no-op; string is managed by GUC machinery */
}
static bool check_quiet_hours_end(char **newval, void **extra, GucSource source)
{
    if (newval && *newval && **newval)
        validate_hhmm_or_error(*newval, "sql_firewall.quiet_hours_end");
    return true;
}
static void assign_quiet_hours_end(const char *newval, void *extra)
{
    /* no-op */
}

/**
 * Checks role-to-IP binding like "role@1.2.3.4,other@10.0.0.1".
 * If any binding exists for a role, only listed IPs are allowed.
 * If no binding for a role, allow (feature acts as per-role allowlist).
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
        return true;

    if (!role || !*role) return true;
    if (!ip   || !*ip)   return true;

    list_copy = pstrdup(role_ip_bindings);
    tok = strtok(list_copy, ",");

    while (tok)
    {
        /* trim spaces */
        while (*tok && isspace((unsigned char)*tok)) tok++;
        {
            char *end = tok + strlen(tok) - 1;
            while (end > tok && isspace((unsigned char)*end)) *end-- = '\0';
        }

        atpos = strchr(tok, '@');
        if (atpos && atpos > tok && *(atpos + 1))
        {
            *atpos = '\0';
            entry_role = tok;
            entry_ip   = atpos + 1;

            if (pg_strcasecmp(role, entry_role) == 0)
            {
                has_any_binding_for_role = true;
                if (strcmp(ip, entry_ip) == 0)
                {
                    pfree(list_copy);
                    return true;
                }
            }
        }

        tok = strtok(NULL, ",");
    }

    pfree(list_copy);
    return !has_any_binding_for_role ? true : false;
}

/**
 * Case-insensitive, whole-word match for blacklisted keywords separated by commas.
 * Returns the matched keyword or NULL.
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
 * Returns true if current time is within quiet hours. Input strings are validated
 * by GUC check hooks; if unset/empty, feature is skipped.
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
        return false;

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
 * Checks if the application_name is explicitly blocked (case-insensitive).
 * Returns the blocked app name or NULL.
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
 * Checks if client IP is in the global blocked list.
 * Returns the blocked IP string or NULL.
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

/* Per-command limit reader */
static int get_command_limit(const char *cmd)
{
    if (strcmp(cmd, "SELECT") == 0) return select_limit_count;
    if (strcmp(cmd, "INSERT") == 0) return insert_limit_count;
    if (strcmp(cmd, "UPDATE") == 0) return update_limit_count;
    if (strcmp(cmd, "DELETE") == 0) return delete_limit_count;
    return 0;
}

/* Firewalled activity logger (SPI). Errors are suppressed into WARNING. */
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
        (void)ret; /* silence unused warning if not checked */

        if (SPI_tuptable != NULL)
            SPI_freetuptable(SPI_tuptable);

        if (spi_started_here)
            SPI_finish();
    }
    PG_CATCH();
    {
        if (spi_started_here)
            SPI_finish();
        FlushErrorState();
        elog(WARNING, "sql_firewall: Failed to log action to activity log");
    }
    PG_END_TRY();
}

/**
 * Checks DB regex rules for a BLOCK match. Uses a prepared plan each call
 * (not cached globally to avoid lifecycle issues across reloads).
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

        plan = SPI_prepare(
            "SELECT EXISTS (SELECT 1 FROM public.sql_firewall_regex_rules "
            "WHERE is_active = true AND action = 'BLOCK' AND $1 ~* pattern)",
            1, &q_type);
        if (plan == NULL)
            elog(ERROR, "SPI_prepare failed for regex check");

        q_datum = CStringGetTextDatum(query_string);
        ret = SPI_execute_plan(plan, &q_datum, &q_null, true, 1);
        (void)ret;

        if (SPI_tuptable != NULL)
        {
            if (SPI_processed > 0)
            {
                bool is_null;
                Datum d = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &is_null);
                if (!is_null)
                    match_found = DatumGetBool(d);
            }
            SPI_freetuptable(SPI_tuptable);
        }

        if (plan != NULL)
            SPI_freeplan(plan);

        if (spi_started_here)
            SPI_finish();
    }
    PG_CATCH();
    {
        if (plan != NULL)
            SPI_freeplan(plan);
        if (spi_started_here)
            SPI_finish();
        FlushErrorState();
        return false;
    }
    PG_END_TRY();

    return match_found;
}

/* ----------------------- Utility: command skipper ----------------------- */

/* Lowercase strstr-based filter to skip internal/maintenance commands. */
static bool should_skip_command(const char *q)
{
    int n;
    char *lc;
    /* Keep needles and flags at top (avoid C90 mixed declarations warning) */
    const char *needles[] = {
        "pg_reload_conf", "set ", "reset ", "show ", "discard", "load ",
        "checkpoint", "vacuum", "analyze", "explain", "deallocate", "prepare ",
        "begin", "start transaction", "commit", "rollback", "savepoint", "release savepoint"
    };
    bool skip = false;
    size_t i;

    if (!q || !*q) return true;
    if (!skip_internal_commands) return false;

    n = (int) strlen(q);
    lc = palloc(n + 1);
    for (i = 0; i < (size_t)n; i++) lc[i] = (char) tolower((unsigned char)q[i]);
    lc[n] = '\0';

    for (i = 0; i < sizeof(needles)/sizeof(needles[0]); i++) {
        if (strstr(lc, needles[i])) { skip = true; break; }
    }
    pfree(lc);
    return skip;
}

/* ----------------------- Firewall Core ----------------------- */

/**
 * Main firewall check. Order of checks:
 * 1) Fast outs (inside_firewall, NULL, skip internals, superuser)
 * 2) Non-SPI checks (quiet hours, keyword blacklist)
 * 3) SPI-backed checks (regex, rate limits, rule engine)
 */
static void check_firewall(const char *query)
{
    const char *cmd = "OTHER";
    const char *kw = NULL;
    char *role = NULL;
    char *db_name = NULL;
    bool spi_started = false;
    List *tree = NULL;

    /* Re-entrancy guard */
    if (inside_firewall) return;
    inside_firewall = true;

    /* Quick outs */
    if (query == NULL || *query == '\0') { inside_firewall = false; return; }
    if (should_skip_command(query))      { inside_firewall = false; return; }

    /* Superusers are exempt from firewall checks */
    if (superuser()) {
        inside_firewall = false;
        return;
    }

    role = GetUserNameFromId(GetUserId(), false);
    if (!role) { inside_firewall = false; return; }

    /* --- Stage 1: Non-SPI checks --- */
    if (is_in_quiet_hours())
    {
        inside_firewall = false;
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
        inside_firewall = false;
        ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR_OR_ACCESS_RULE_VIOLATION),
                        errmsg("sql_firewall: Blocked due to blacklisted keyword '%s'.", kw)));
        return;
    }

    /* --- Stage 2: SPI-backed checks --- */
    PG_TRY();
    {
        /* Never enter SPI outside of a valid transaction state */
        if (!IsTransactionState()) {
            inside_firewall = false;
            return;
        }

        if (SPI_connect() != SPI_OK_CONNECT)
            elog(ERROR, "SPI_connect failed in check_firewall");
        spi_started = true;

        if (SPI_execute("SELECT current_database()", true, 1) == SPI_OK_SELECT)
        {
            if (SPI_processed > 0 && SPI_tuptable && SPI_tuptable->vals[0])
                db_name = pstrdup(SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1));
            if (SPI_tuptable) SPI_freetuptable(SPI_tuptable);
        }

        /* Parse query to detect command type */
        tree = pg_parse_query(query);
        if (tree && list_length(tree) == 1)
        {
            RawStmt *stmt = linitial_node(RawStmt, tree);
            if (IsA(stmt->stmt, InsertStmt)) cmd = "INSERT";
            else if (IsA(stmt->stmt, UpdateStmt)) cmd = "UPDATE";
            else if (IsA(stmt->stmt, DeleteStmt)) cmd = "DELETE";
            else if (IsA(stmt->stmt, SelectStmt)) cmd = "SELECT";
        }
        if (tree) { list_free_deep(tree); tree = NULL; }

        /* Regex block rules */
        if (query_matches_regex_block_rule(query, true))
        {
            log_firewall_action(role, db_name, "BLOCKED", "Regex pattern match", query, cmd, true);
            ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                            errmsg("sql_firewall: Query blocked by security regex pattern.")));
        }

        /* Global rate limit */
        if (enable_rate_limiting)
        {
            int query_count = 0;
            char *ratelimit_sql = psprintf(
                "SELECT COUNT(*) FROM public.sql_firewall_activity_log "
                "WHERE role_name = %s AND log_time > now() - interval '%d seconds' AND action <> 'LEARNED (Command)'",
                quote_literal_cstr(role), rate_limit_seconds);

            if (SPI_execute(ratelimit_sql, true, 1) == SPI_OK_SELECT)
            {
                if (SPI_processed > 0 && SPI_tuptable && SPI_tuptable->vals[0]) {
                    char *count_str = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
                    if (count_str) { query_count = atoi(count_str); pfree(count_str); }
                }
                if (SPI_tuptable) SPI_freetuptable(SPI_tuptable);
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

        /* Per-command rate limits */
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

                if (SPI_execute(cmd_sql, true, 1) == SPI_OK_SELECT)
                {
                    if (SPI_processed > 0 && SPI_tuptable && SPI_tuptable->vals[0]) {
                        char *count_str = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
                        if (count_str) { cmd_count = atoi(count_str); pfree(count_str); }
                    }
                    if (SPI_tuptable) SPI_freetuptable(SPI_tuptable);
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

        /* Rule engine (command-type approvals) */
        if (strcmp(cmd, "OTHER") != 0)
        {
            char *rule_sql = psprintf(
                "SELECT is_approved FROM public.sql_firewall_command_approvals "
                "WHERE role_name = %s AND command_type = %s",
                quote_literal_cstr(role), quote_literal_cstr(cmd));
            {
                int ret = SPI_execute(rule_sql, true, 1);
                (void)ret;
            }
            pfree(rule_sql);

            if (SPI_tuptable && SPI_processed > 0)
            {
                bool is_null;
                bool is_approved = DatumGetBool(
                    SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &is_null));
                if (is_null) is_approved = false;
                SPI_freetuptable(SPI_tuptable);

                if (is_approved) {
                    log_firewall_action(role, db_name, "ALLOWED", "Approved command type", query, cmd, true);
                } else {
                    if (sql_firewall_mode == SQL_FIREWALL_MODE_PERMISSIVE) {
                        log_firewall_action(role, db_name, "ALLOWED (PERMISSIVE)", "Command type approval pending", query, cmd, true);
                    } else { /* ENFORCE or LEARN should block here */
                        log_firewall_action(role, db_name, "BLOCKED", "Command type approval pending", query, cmd, true);
                        ereport(ERROR, (errmsg("sql_firewall: Approval for command '%s' is pending for role '%s'", cmd, role)));
                    }
                }
            }
            else
            {
                if (SPI_tuptable) SPI_freetuptable(SPI_tuptable);

                if (sql_firewall_mode == SQL_FIREWALL_MODE_LEARN)
                {
                    Datum insert_vals[2];
                    Oid   insert_types[2] = {NAMEOID, TEXTOID};
                    char  insert_nulls[3] = {' ', ' ', '\0'};
                    int   insert_ret;

                    insert_vals[0] = DirectFunctionCall1(namein, CStringGetDatum(role));
                    insert_vals[1] = CStringGetTextDatum(cmd);

                    insert_ret = SPI_execute_with_args(
                        "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type) "
                        "VALUES ($1, $2) ON CONFLICT DO NOTHING",
                        2, insert_types, insert_vals, insert_nulls, false, 0);
                    (void)insert_ret;

                    if (SPI_tuptable) SPI_freetuptable(SPI_tuptable);

                    log_firewall_action(role, db_name, "LEARNED (Command)", "New command type detected", query, cmd, true);
                }
                else if (sql_firewall_mode == SQL_FIREWALL_MODE_PERMISSIVE)
                {
                    log_firewall_action(role, db_name, "ALLOWED (PERMISSIVE)", "No rule for command type", query, cmd, true);
                }
                else /* ENFORCE */
                {
                    log_firewall_action(role, db_name, "BLOCKED", "No rule for command type", query, cmd, true);
                    ereport(ERROR, (errmsg("sql_firewall: No rule found for command '%s' for role '%s'", cmd, role)));
                }
            }
        }
        else
        {
            /* Non-tracked commands (e.g., SET, VACUUM) reach here if not skipped earlier */
            log_firewall_action(role, db_name, "ALLOWED", "Command type is 'OTHER'", query, cmd, true);
        }

        /* Cleanup */
        SPI_finish();
        if (db_name) { pfree(db_name); db_name = NULL; }
        if (role)    { pfree(role);    role    = NULL; }
        inside_firewall = false;
    }
    PG_CATCH();
    {
        if (tree)    { list_free_deep(tree); tree = NULL; }
        if (db_name) { pfree(db_name); db_name = NULL; }
        if (role)    { pfree(role);    role    = NULL; }
        if (spi_started) SPI_finish();
        inside_firewall = false;
        PG_RE_THROW();
    }
    PG_END_TRY();
}

/* ----------------------- Hook Wrappers ----------------------- */

/* DML (SELECT/INSERT/UPDATE/DELETE) entrypoint */
static void sql_firewall_executor_start_hook(QueryDesc *queryDesc, int eflags)
{
    if (queryDesc &&
        queryDesc->sourceText &&
        queryDesc->plannedstmt &&
        queryDesc->plannedstmt->commandType != CMD_UTILITY)
    {
        check_firewall(queryDesc->sourceText);
    }

    if (prev_executor_start_hook)
        prev_executor_start_hook(queryDesc, eflags);
    else
        standard_ExecutorStart(queryDesc, eflags);
}

/* Utility commands (CREATE/ALTER/DROP/etc.) entrypoint */
static void sql_firewall_process_utility_hook(PlannedStmt *pstmt, const char *queryString,
                                              bool readOnlyTree, ProcessUtilityContext context,
                                              ParamListInfo params, QueryEnvironment *queryEnv,
                                              DestReceiver *dest, QueryCompletion *qc)
{
    if (pstmt && pstmt->commandType == CMD_UTILITY && queryString && !should_skip_command(queryString))
        check_firewall(queryString);

    if (prev_process_utility_hook)
        prev_process_utility_hook(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
    else
        standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
}

/* ----------------------- Client Authentication Hook ----------------------- */

static void sql_firewall_client_auth_hook(Port *port, int status)
{
    if (port)
    {
        const char *addr = (port->remote_host && port->remote_host[0]) ? port->remote_host : NULL;
        const char *app  = port->application_name;
        const char *user = port->user_name;

        /* Optional: never block postgres superuser at auth stage */
        if (allow_superuser_bypass_auth && user && strcmp(user, "postgres") == 0)
            goto chain_auth;

        if (addr && is_ip_blocked(addr))
        {
            ereport(FATAL,
                    (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
                     errmsg("sql_firewall: Connection from blocked IP address '%s' is not allowed.", addr)));
        }

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

chain_auth:
    if (prev_client_auth_hook)
        prev_client_auth_hook(port, status);
}

/* ----------------------- Module Init / Fini ----------------------- */

void _PG_init(void)
{
    /* Core mode and feature flags */
    DefineCustomEnumVariable("sql_firewall.mode", "Sets the firewall operation mode.", NULL,
                             &sql_firewall_mode, SQL_FIREWALL_MODE_LEARN, mode_options,
                             PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomBoolVariable("sql_firewall.enable_keyword_scan", "Enables scanning for blacklisted keywords.", NULL,
                             &enable_keyword_scan, false, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomStringVariable("sql_firewall.blacklisted_keywords", "Comma-separated list of keywords to block.", NULL,
                               &blacklisted_keywords, "drop,truncate", PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomBoolVariable("sql_firewall.enable_quiet_hours", "Enables quiet hours.", NULL,
                             &enable_quiet_hours, false, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomStringVariable("sql_firewall.quiet_hours_start", "Start time for quiet hours (HH:MM).", NULL,
                               &quiet_hours_start, "22:00", PGC_SUSET, 0,
                               check_quiet_hours_start, assign_quiet_hours_start, NULL);

    DefineCustomStringVariable("sql_firewall.quiet_hours_end", "End time for quiet hours (HH:MM).", NULL,
                               &quiet_hours_end, "06:00", PGC_SUSET, 0,
                               check_quiet_hours_end, assign_quiet_hours_end, NULL);

    DefineCustomBoolVariable("sql_firewall.enable_rate_limiting", "Enables query rate limiting.", NULL,
                             &enable_rate_limiting, false, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable("sql_firewall.rate_limit_count", "Number of queries allowed per window.", NULL,
                            &rate_limit_count, 100, 1, INT_MAX, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable("sql_firewall.rate_limit_seconds", "Time window for rate limit in seconds.", NULL,
                            &rate_limit_seconds, 60, 1, INT_MAX, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable("sql_firewall.select_limit_count", "Max SELECTs per window for per-command limit.", NULL,
                            &select_limit_count, 0, 0, INT_MAX, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable("sql_firewall.insert_limit_count", "Max INSERTs per window for per-command limit.", NULL,
                            &insert_limit_count, 0, 0, INT_MAX, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable("sql_firewall.update_limit_count", "Max UPDATEs per window for per-command limit.", NULL,
                            &update_limit_count, 0, 0, INT_MAX, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable("sql_firewall.delete_limit_count", "Max DELETEs per window for per-command limit.", NULL,
                            &delete_limit_count, 0, 0, INT_MAX, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable("sql_firewall.command_limit_seconds", "Time window in seconds for per-command rate limit.", NULL,
                            &command_limit_seconds, 60, 0, INT_MAX, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomBoolVariable("sql_firewall.enable_application_blocking", "Enables blocking based on application_name.", NULL,
                             &enable_application_blocking, false, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomStringVariable("sql_firewall.blocked_applications", "Comma-separated list of application_names to block.", NULL,
                               &blocked_applications, "", PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomBoolVariable("sql_firewall.enable_regex_scan", "Enables scanning queries against regex rules.", NULL,
                             &enable_regex_scan, true, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomBoolVariable("sql_firewall.enable_ip_blocking", "Enables blocking based on client IP address.", NULL,
                             &enable_ip_blocking, false, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomStringVariable("sql_firewall.blocked_ips", "Comma-separated list of IP addresses to block.", NULL,
                               &blocked_ips, "", PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomBoolVariable("sql_firewall.enable_role_ip_binding", "If on, restricts roles to specific IPs defined in role_ip_bindings.", NULL,
                             &enable_role_ip_binding, false, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomStringVariable("sql_firewall.role_ip_bindings", "Comma-separated list like: role1@10.0.0.5,role2@192.168.1.100", NULL,
                               &role_ip_bindings, "", PGC_SUSET, 0, NULL, NULL, NULL);

    /* Safety toggles */
    DefineCustomBoolVariable("sql_firewall.skip_internal_commands", "Skip internal/maintenance commands in hooks.", NULL,
                             &skip_internal_commands, true, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomBoolVariable("sql_firewall.allow_superuser_bypass_auth", "Bypass auth-stage blocking for superuser 'postgres'.", NULL,
                             &allow_superuser_bypass_auth, true, PGC_SUSET, 0, NULL, NULL, NULL);

    /* Install hooks */
    prev_executor_start_hook = ExecutorStart_hook;
    ExecutorStart_hook = sql_firewall_executor_start_hook;

    prev_process_utility_hook = ProcessUtility_hook;
    ProcessUtility_hook = sql_firewall_process_utility_hook;

    prev_client_auth_hook = ClientAuthentication_hook;
    ClientAuthentication_hook = sql_firewall_client_auth_hook;
}

void _PG_fini(void)
{
    /* Uninstall hooks (restore chain) */
    ExecutorStart_hook        = prev_executor_start_hook;
    ProcessUtility_hook       = prev_process_utility_hook;
    ClientAuthentication_hook = prev_client_auth_hook;
}

/* ----------------------- SQL-Callable Functions ----------------------- */

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
    if (SPI_tuptable) SPI_freetuptable(SPI_tuptable);
    SPI_finish();

    PG_RETURN_INT64(processed);
}

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
    if (SPI_tuptable) SPI_freetuptable(SPI_tuptable);
    SPI_finish();

    PG_RETURN_INT64(processed);
}

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
    if (SPI_tuptable) SPI_freetuptable(SPI_tuptable);
    SPI_finish();

    PG_RETURN_INT64(processed);
}

