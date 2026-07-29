#!/bin/sh
set -eu

REPOSITORY_URL=${OPENPPP_MANAGEMENT_REPOSITORY:-https://github.com/picetor/openppp_management.git}
INSTALL_DIR=${OPENPPP_MANAGEMENT_DIR:-/opt/openppp_management}

prompt() {
    label=$1
    default_value=$2
    printf '%s [%s]: ' "$label" "$default_value"
    IFS= read -r answer
    if [ -n "$answer" ]; then
        printf '%s' "$answer"
    else
        printf '%s' "$default_value"
    fi
}

prompt_secret() {
    label=$1
    default_value=$2
    printf '%s' "$label"
    if [ -t 0 ]; then
        stty -echo
    fi
    IFS= read -r answer
    if [ -t 0 ]; then
        stty echo
        printf '\n'
    fi
    if [ -n "$answer" ]; then
        printf '%s' "$answer"
    else
        printf '%s' "$default_value"
    fi
}

random_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 24
    else
        od -An -N24 -tx1 /dev/urandom | tr -d ' \n'
    fi
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing required command: $1" >&2
        exit 1
    fi
}

require_command git
require_command docker
if ! docker compose version >/dev/null 2>&1; then
    echo "Docker Compose v2 is required (docker compose)." >&2
    exit 1
fi

echo
echo "OpenPPP Management installer"
echo
echo "Database type:"
echo "  1) SQLite (recommended for personal/small deployments)"
echo "  2) MySQL (existing external server)"
echo "  3) MySQL (create a local Docker container)"
database_choice=$(prompt "Select" "1")

bind_address=$(prompt "Panel bind address" "127.0.0.1")
bind_port=$(prompt "Panel bind port" "8080")
public_url=$(prompt "Public URL" "http://$bind_address:$bind_port")
admin_username=$(prompt "Admin username" "admin")
generated_admin_password=$(random_secret)
admin_password=$(prompt_secret "Admin password (Enter to generate): " "$generated_admin_password")
generated_communication_key=$(random_secret)
communication_key=$(prompt_secret "Node communication key (Enter to generate): " "$generated_communication_key")

database_driver=sqlite
database_dsn=
database_path=/app/data/management.db
compose_profile=
mysql_password=
mysql_root_password=

case "$database_choice" in
    1)
        ;;
    2)
        database_driver=mysql
        mysql_host=$(prompt "MySQL address" "127.0.0.1")
        mysql_port=$(prompt "MySQL port" "3306")
        mysql_database=$(prompt "MySQL database" "openppp_management")
        mysql_username=$(prompt "MySQL username" "openppp")
        mysql_password=$(prompt_secret "MySQL password: " "")
        if [ -z "$mysql_password" ]; then
            echo "MySQL password cannot be empty." >&2
            exit 1
        fi
        if [ "$mysql_host" = "127.0.0.1" ] || [ "$mysql_host" = "localhost" ]; then
            mysql_host=host.docker.internal
        fi
        database_dsn="$mysql_username:$mysql_password@tcp($mysql_host:$mysql_port)/$mysql_database?charset=utf8mb4&parseTime=true&loc=UTC"
        ;;
    3)
        database_driver=mysql
        compose_profile=mysql
        mysql_database=$(prompt "MySQL database" "openppp_management")
        mysql_username=$(prompt "MySQL username" "openppp")
        generated_mysql_password=$(random_secret)
        mysql_password=$(prompt_secret "MySQL password (Enter to generate): " "$generated_mysql_password")
        generated_root_password=$(random_secret)
        mysql_root_password=$(prompt_secret "MySQL root password (Enter to generate): " "$generated_root_password")
        database_dsn="$mysql_username:$mysql_password@tcp(mysql:3306)/$mysql_database?charset=utf8mb4&parseTime=true&loc=UTC"
        ;;
    *)
        echo "Invalid database selection." >&2
        exit 1
        ;;
esac

install_parent=$(dirname "$INSTALL_DIR")
mkdir -p "$install_parent"
if [ -d "$INSTALL_DIR/.git" ]; then
    git -C "$INSTALL_DIR" pull --ff-only
elif [ -e "$INSTALL_DIR" ]; then
    echo "$INSTALL_DIR already exists but is not a Git repository." >&2
    exit 1
else
    git clone "$REPOSITORY_URL" "$INSTALL_DIR"
fi

umask 077
{
    printf 'OPENPPP2_LISTEN=0.0.0.0:8080\n'
    printf 'OPENPPP2_BIND_ADDRESS=%s:%s\n' "$bind_address" "$bind_port"
    printf 'OPENPPP2_PUBLIC_URL=%s\n' "$public_url"
    printf 'OPENPPP2_ADMIN_USERNAME=%s\n' "$admin_username"
    printf 'OPENPPP2_ADMIN_PASSWORD=%s\n' "$admin_password"
    printf 'OPENPPP2_COMMUNICATION_KEY=%s\n' "$communication_key"
    printf 'OPENPPP2_DATABASE_DRIVER=%s\n' "$database_driver"
    printf 'OPENPPP2_DATABASE_PATH=%s\n' "$database_path"
    printf 'OPENPPP2_DATABASE_DSN=%s\n' "$database_dsn"
    printf 'OPENPPP2_SESSION_TTL_HOURS=168\n'
    printf 'OPENPPP2_NODE_OFFLINE_SECONDS=90\n'
    printf 'MYSQL_DATABASE=%s\n' "${mysql_database:-openppp_management}"
    printf 'MYSQL_USER=%s\n' "${mysql_username:-openppp}"
    printf 'MYSQL_PASSWORD=%s\n' "$mysql_password"
    printf 'MYSQL_ROOT_PASSWORD=%s\n' "$mysql_root_password"
} >"$INSTALL_DIR/.env"

mkdir -p "$INSTALL_DIR/data"
cd "$INSTALL_DIR"
if [ "$database_driver" = "sqlite" ]; then
    docker compose -f compose.sqlite.yaml up -d --build
elif [ "$compose_profile" = "mysql" ]; then
    docker compose --profile mysql up -d --build
else
    docker compose up -d --build management
fi

echo
echo "Installation complete."
echo "Panel: $public_url"
echo "Admin username: $admin_username"
if [ "$admin_password" = "$generated_admin_password" ]; then
    echo "Generated admin password: $admin_password"
fi
if [ "$communication_key" = "$generated_communication_key" ]; then
    echo "Generated node communication key: $communication_key"
fi
echo "Configuration: $INSTALL_DIR/.env"
