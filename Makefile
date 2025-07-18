EXTENSION = password_check
MODULES   = password_check
DATA      = password_check--1.0.sql
# CONTROL satırı kaldırıldı.

PG_CONFIG = /usr/pgsql-16/bin/pg_config
PGXS      := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
