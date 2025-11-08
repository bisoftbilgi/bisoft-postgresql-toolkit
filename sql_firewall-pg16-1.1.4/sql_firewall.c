/*
 * SQL Firewall Extension for PostgreSQL 16
 * Version: 1.1.5 (Rocky Linux 9 / SPI-safe)
 * Author: Çağhan Uzundurukan
 *
 * - Learn, Permissive, Enforce modları
 * - Regex / Keyword / Rate-limit / Quiet Hours / IP & App blocking
 * - Superuser bypass
 * - Activity log + command approvals tablolarına SPI ile yazma
 */

#include "postgres.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "utils/guc.h"
#include "utils/builtins.h"
#include "utils/timestamp.h"
#include "utils/acl.h"
#include "utils/lsyscache.h"
#include "utils/elog.h"
#include "commands/dbcommands.h"
#include "commands/user.h"
#include "lib/stringinfo.h"
#include "executor/spi.h"
#include "tcop/utility.h"
#include "tcop/tcopprot.h"
#include "access/xact.h"
#include "catalog/pg_type.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "storage/proc.h"
#include "postmaster/postmaster.h"
#include "libpq/auth.h"

PG_MODULE_MAGIC;

/* ---------- ENUM TANIMLARI ---------- */

typedef enum
{
    FIREWALL_MODE_LEARN,
    FIREWALL_MODE_PERMISSIVE,
    FIREWALL_MODE_ENFORCE
} FirewallMode;

/* ---------- GLOBAL HOOKLAR ---------- */
static ProcessUtility_hook_type prev_ProcessUtility = NULL;
static ExecutorStart_hook_type prev_ExecutorStart = NULL;
static ClientAuthentication_hook_type prev_ClientAuth = NULL;

/* ---------- GUC DEĞİŞKENLERİ ---------- */

/* Mod yönetimi */
static char *sql_firewall_mode_str = "learn";
static FirewallMode sql_firewall_mode = FIREWALL_MODE_LEARN;

/* Keyword / Regex kontrolü */
static bool enable_keyword_scan = false;
static bool enable_regex_scan = false;
static char *blacklisted_keywords = NULL;

/* Rate limiting */
static bool enable_rate_limiting = false;
static int rate_limit_count = 5;
static int rate_limit_seconds = 10;

/* Quiet hours */
static bool enable_quiet_hours = false;
static char *quiet_hours_start = NULL;
static char *quiet_hours_end = NULL;

/* Uygulama ve IP bloklama */
static bool enable_application_blocking = false;
static char *blocked_applications = NULL;

static bool enable_ip_blocking = false;
static char *blocked_ips = NULL;

/* Role-IP eşleşme */
static bool enable_role_ip_binding = false;

/* Superuser bypass */
static bool allow_superuser_bypass = true;

/* Dahili komut atlama */
static bool skip_internal_commands = true;

/* Regex kontrolü için SPI sorgusu (CACHED değil, transaction başına açılır) */
#define REGEX_MATCH_SQL "SELECT pattern FROM public.sql_firewall_regex_rules WHERE is_active = true AND action = 'BLOCK'"

/* Loglama ve onay tabloları */
#define ACTIVITY_LOG_TABLE   "public.sql_firewall_activity_log"
#define APPROVALS_TABLE      "public.sql_firewall_command_approvals"

/* ---------- FORWARD DECLARATIONS ---------- */

void _PG_init(void);
void _PG_fini(void);

static void sql_firewall_ProcessUtility(PlannedStmt *pstmt, const char *queryString,
                                        bool readOnlyTree, ProcessUtilityContext context,
                                        ParamListInfo params, QueryEnvironment *queryEnv,
                                        DestReceiver *dest, QueryCompletion *qc);

static void sql_firewall_ExecutorStart(QueryDesc *queryDesc, int eflags);
static void sql_firewall_ClientAuth(Port *port, int status);

static void check_firewall(const char *query, const char *cmdtag);
static bool is_in_quiet_hours(void);
static bool contains_blacklisted_keyword(const char *query);
static bool query_matches_regex_block_rule(const char *query);
static bool should_skip_command(const char *query);
static void log_firewall_action(const char *role, const char *dbname,
                                const char *action, const char *reason,
                                const char *query_text, const char *cmd_type);

/* SQL fonksiyonları */
PG_FUNCTION_INFO_V1(sql_firewall_reset_log_for_role);
PG_FUNCTION_INFO_V1(sql_firewall_approve_all_for_role);
PG_FUNCTION_INFO_V1(sql_firewall_reject_all_for_role);

/* ============================================================
 *  BÖLÜM 2 – YARDIMCI FONKSİYONLAR
 * ============================================================ */

#include <time.h>

/* Sessiz saat aralığında mıyız? */
static bool
is_in_quiet_hours(void)
{
    if (!enable_quiet_hours || !quiet_hours_start || !quiet_hours_end)
        return false;

    int sh, sm, eh, em;
    if (sscanf(quiet_hours_start, "%d:%d", &sh, &sm) != 2)
        return false;
    if (sscanf(quiet_hours_end, "%d:%d", &eh, &em) != 2)
        return false;

    TimestampTz now = GetCurrentTimestamp();
    struct pg_tm tm;
    fsec_t fsec;
    pg_localtime(&now, session_timezone, &tm);
    int now_min = tm.tm_hour * 60 + tm.tm_min;
    int start_min = sh * 60 + sm;
    int end_min = eh * 60 + em;

    if (start_min <= end_min)
        return (now_min >= start_min && now_min <= end_min);
    else
        return (now_min >= start_min || now_min <= end_min);
}

/* IP engelleme kontrolü */
static bool
is_ip_blocked(const char *client_ip)
{
    if (!enable_ip_blocking || client_ip == NULL || blocked_ips == NULL)
        return false;

    char *copy = pstrdup(blocked_ips);
    char *token = strtok(copy, ",");
    while (token)
    {
        if (strcmp(token, client_ip) == 0)
        {
            pfree(copy);
            return true;
        }
        token = strtok(NULL, ",");
    }
    pfree(copy);
    return false;
}

/* Uygulama engelleme kontrolü */
static bool
is_application_blocked(const char *appname)
{
    if (!enable_application_blocking || appname == NULL || blocked_applications == NULL)
        return false;

    char *copy = pstrdup(blocked_applications);
    char *token = strtok(copy, ",");
    while (token)
    {
        if (strcmp(token, appname) == 0)
        {
            pfree(copy);
            return true;
        }
        token = strtok(NULL, ",");
    }
    pfree(copy);
    return false;
}

/* Basit keyword kontrolü */
static bool
contains_blacklisted_keyword(const char *query)
{
    if (!enable_keyword_scan || !blacklisted_keywords || query == NULL)
        return false;

    char *q = pstrdup(query);
    char *kwcopy = pstrdup(blacklisted_keywords);
    char *token = strtok(kwcopy, ",");
    while (token)
    {
        if (pg_strcasestr(q, token))
        {
            pfree(q);
            pfree(kwcopy);
            return true;
        }
        token = strtok(NULL, ",");
    }
    pfree(q);
    pfree(kwcopy);
    return false;
}

/* Regex kurallarına göre sorgu taraması */
static bool
query_matches_regex_block_rule(const char *query)
{
    if (!enable_regex_scan || query == NULL)
        return false;

    bool found = false;

    if (SPI_connect() != SPI_OK_CONNECT)
        return false;

    int ret = SPI_execute(REGEX_MATCH_SQL, true, 0);
    if (ret == SPI_OK_SELECT && SPI_processed > 0)
    {
        for (uint64 i = 0; i < SPI_processed; i++)
        {
            bool isnull;
            char *pattern = SPI_getvalue(SPI_tuptable->vals[i],
                                         SPI_tuptable->tupdesc, 1);
            if (pattern && pg_regexec(pattern, query, REG_ICASE))
            {
                found = true;
                break;
            }
        }
    }

    SPI_finish();
    return found;
}

/* Dahili (önemsiz) komutları atla */
static bool
should_skip_command(const char *query)
{
    if (!skip_internal_commands || query == NULL)
        return false;

    const char *needles[] = {
        "SET ", "SHOW ", "RESET ", "BEGIN", "COMMIT", "ROLLBACK",
        "DISCARD", "SAVEPOINT", "RELEASE", "DEALLOCATE", "CLOSE", NULL};

    for (int i = 0; needles[i] != NULL; i++)
    {
        if (pg_strncasecmp(query, needles[i], strlen(needles[i])) == 0)
            return true;
    }
    return false;
}


