#!/bin/bash
# Password Profile Pure - Installation Script for PostgreSQL 16
# Usage: ./install.sh (will ask for sudo when needed)

set -e

PG_VERSION=16
PG_CONFIG=/usr/pgsql-${PG_VERSION}/bin/pg_config
EXTENSION_NAME=password_profile_pure

echo "=== Password Profile Pure Installer ==="
echo "PostgreSQL Version: ${PG_VERSION}"
echo ""

# Check if PostgreSQL is installed
if [ ! -f "$PG_CONFIG" ]; then
    echo "Error: PostgreSQL ${PG_VERSION} not found at $PG_CONFIG"
    exit 1
fi

# Build the extension (as regular user, not root)
echo "Building extension..."
PGRX_PG_CONFIG_PATH=$PG_CONFIG cargo build --release --features pg${PG_VERSION} --no-default-features

# Get PostgreSQL directories
LIB_DIR=$($PG_CONFIG --pkglibdir)
SHARE_DIR=$($PG_CONFIG --sharedir)/extension

echo "Installing to:"
echo "  Library: $LIB_DIR"
echo "  Extension: $SHARE_DIR"
echo ""

# Install files (needs sudo)
echo "Installing files (requires sudo)..."
sudo cp target/release/lib${EXTENSION_NAME}.so ${LIB_DIR}/${EXTENSION_NAME}.so
sudo chmod 755 ${LIB_DIR}/${EXTENSION_NAME}.so

sudo cp sql/${EXTENSION_NAME}--0.0.0.sql ${SHARE_DIR}/
sudo cp ${EXTENSION_NAME}.control ${SHARE_DIR}/
sudo chmod 644 ${SHARE_DIR}/${EXTENSION_NAME}--0.0.0.sql
sudo chmod 644 ${SHARE_DIR}/${EXTENSION_NAME}.control

sudo cp blacklist.txt ${SHARE_DIR}/password_profile_blacklist.txt
sudo chmod 644 ${SHARE_DIR}/password_profile_blacklist.txt

echo ""
echo "Installation completed successfully!"
echo ""
echo "Next steps:"
echo "1. Add to postgresql.conf:"
echo "   shared_preload_libraries = 'password_profile_pure'"
echo ""
echo "2. Restart PostgreSQL:"
echo "   sudo systemctl restart postgresql-${PG_VERSION}"
echo ""
echo "3. Create extension in database:"
echo "   CREATE EXTENSION password_profile_pure;"
