#include "postgres.h"
#include "libpq/auth.h"

const char *password_profile_port_username(Port *port) {
    if (port == NULL || port->user_name == NULL) {
        return NULL;
    }
    return port->user_name;
}

ClientAuthentication_hook_type password_profile_register_client_auth_hook(
    ClientAuthentication_hook_type hook
) {
    ClientAuthentication_hook_type previous = ClientAuthentication_hook;
    ClientAuthentication_hook = hook;
    return previous;
}
