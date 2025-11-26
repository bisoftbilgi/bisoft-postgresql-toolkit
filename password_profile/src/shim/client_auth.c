#include "postgres.h"
#include "libpq/auth.h"
#include "libpq/hba.h"
#include "utils/elog.h"
#include "utils/errcodes.h"
#include "miscadmin.h"
#include "catalog/pg_authid.h"
#include "utils/syscache.h"
#include "utils/builtins.h"

const char *password_profile_port_username(Port *port) {
    if (port == NULL || port->user_name == NULL) {
        return NULL;
    }
    return port->user_name;
}

/*
 * Check if the user exists in pg_authid.
 * Returns 1 if user exists, 0 if not, -1 on error.
 * 
 * This allows us to distinguish:
 * - Password wrong for existing user (track it)
 * - User does not exist (don't track it)
 */
int password_profile_user_exists(const char *username) {
    if (username == NULL || username[0] == '\0') {
        return -1;
    }
    
    /* Check in pg_authid (requires reading catalog) */
    HeapTuple roleTup;
    
    roleTup = SearchSysCache1(AUTHNAME, CStringGetDatum(username));
    if (HeapTupleIsValid(roleTup)) {
        ReleaseSysCache(roleTup);
        return 1; /* User exists */
    }
    
    return 0; /* User does not exist */
}

/*
 * Predict the SQLSTATE that auth_failed() would emit for the given
 * authentication status. This mirrors auth_failed()'s errcode logic so
 * extensions can distinguish password errors (28P01) from other failures.
 */
int password_profile_get_last_sqlstate(Port *port, int status) {
    if (port == NULL || port->hba == NULL) {
        return ERRCODE_INTERNAL_ERROR;
    }

    if (status == STATUS_OK) {
        return ERRCODE_SUCCESSFUL_COMPLETION;
    }

    if (status == STATUS_EOF) {
        return ERRCODE_CONNECTION_FAILURE;
    }

    switch (port->hba->auth_method) {
        case uaPassword:
        case uaMD5:
        case uaSCRAM:
            return ERRCODE_INVALID_PASSWORD;
        case uaCert:
        case uaReject:
        case uaImplicitReject:
        case uaTrust:
        case uaIdent:
        case uaPeer:
        case uaGSS:
        case uaSSPI:
        case uaPAM:
        case uaBSD:
        case uaLDAP:
        case uaRADIUS:
        default:
            return ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION;
    }
}

ClientAuthentication_hook_type password_profile_register_client_auth_hook(
    ClientAuthentication_hook_type hook
) {
    ClientAuthentication_hook_type previous = ClientAuthentication_hook;
    ClientAuthentication_hook = hook;
    return previous;
}

void password_profile_raise_lockout_error(const char *username, int remaining_seconds) {
    /* Safely handle NULL or empty username */
    const char *safe_username = (username && username[0] != '\0') ? username : "unknown";
    int minutes = remaining_seconds / 60;
    int seconds = remaining_seconds % 60;

    /* Use %s with quote_identifier-like safety (ereport escapes automatically) */
    ereport(FATAL,
            (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
             errmsg("Account locked! Please wait %d minute(s) and %d second(s). Too many failed login attempts.", 
                    minutes, seconds),
             errdetail("User \"%s\" attempted login while locked.", safe_username)));
}
