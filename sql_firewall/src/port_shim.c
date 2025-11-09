#include "postgres.h"
#include "libpq/libpq-be.h"
#include "libpq/pqcomm.h"
#include "libpq/pqformat.h"
#include "lib/stringinfo.h"
#include <netdb.h>
#include <stdbool.h>
#include <string.h>

extern int pg_getnameinfo_all(const struct sockaddr *addr,
                              socklen_t salen,
                              char *node,
                              size_t nodelen,
                              char *service,
                              size_t servicelen,
                              int flags);

const char *
sqlfw_port_application_name(Port *port)
{
    if (port == NULL || port->application_name == NULL || port->application_name[0] == '\0')
        return NULL;
    return port->application_name;
}

bool
sqlfw_port_client_addr(Port *port, char *destination, size_t destination_len)
{
    if (port == NULL || destination == NULL || destination_len == 0)
        return false;

    if (port->remote_host[0] != '\0')
    {
        strlcpy(destination, port->remote_host, destination_len);
        return true;
    }

    if (pg_getnameinfo_all((const struct sockaddr *) &port->raddr.addr,
                           port->raddr.salen,
                           destination,
                           destination_len,
                           NULL,
                           0,
                           NI_NUMERICHOST) == 0)
    {
        return true;
    }

    return false;
}
