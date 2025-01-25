#!/bin/sh
if [ -n "${SOCKD_USER_NAME}" ]; then
    echo "${SOCKD_USER_NAME}"
    if [ -z "${SOCKD_USER_PASSWORD}" ]; then
        echo "Set SOCKD_USER_PASSWORD in .env"
        exit 1
    fi
    adduser -D "${SOCKD_USER_NAME}"
    echo "${SOCKD_USER_NAME}:${SOCKD_USER_PASSWORD}" | chpasswd
    echo "user ${SOCKD_USER_NAME} successfully set"
fi
exec "$@"

