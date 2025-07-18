# Makefile

# Name of the module to be built (the shared library name)
MODULES = sql_firewall

# Files associated with the extension
EXTENSION = sql_firewall
DATA = sql_firewall--0.1.0.sql

# Include the PostgreSQL build infrastructure (PGXS)
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
