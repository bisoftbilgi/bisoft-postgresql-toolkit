EXTENSION = sql_firewall
MODULE_big = sql_firewall
OBJS = sql_firewall.o

DATA = sql_firewall--1.0.sql

PG_CPPFLAGS = -I$(includedir_server) -I$(includedir_internal)

PG_CONFIG = /usr/pgsql-16/bin/pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

