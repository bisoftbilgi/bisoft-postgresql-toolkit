# Extension name
EXTENSION = sql_firewall

# SQL file to be installed with the extension
DATA = sql_firewall--1.0.sql

# Shared library to be built from the C source file
MODULES = sql_firewall

# PostgreSQL build infrastructure
PG_CONFIG = /usr/pgsql-16/bin/pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
