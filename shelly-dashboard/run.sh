#!/usr/bin/with-contenv bashio
set -e
DEVICES="$(bashio::config 'devices')"
NETWORK="$(bashio::config 'network')"
REFRESH="$(bashio::config 'refresh')"
TIMEOUT="$(bashio::config 'timeout')"
MDNS_TIMEOUT="$(bashio::config 'mdns_timeout')"
USER_NAME="$(bashio::config 'user')"
PASSWORD="$(bashio::config 'password')"
USE_MDNS="$(bashio::config 'use_mdns')"
CMD="python3 /app/shelly_dashboard_firmware.py --host 0.0.0.0 --port 5000 --refresh ${REFRESH} --timeout ${TIMEOUT} --mdns-timeout ${MDNS_TIMEOUT}"
[ -n "${DEVICES}" ] && CMD="${CMD} --devices ${DEVICES}"
[ -n "${NETWORK}" ] && CMD="${CMD} --network ${NETWORK}"
[ -n "${USER_NAME}" ] && CMD="${CMD} --user ${USER_NAME}"
[ -n "${PASSWORD}" ] && CMD="${CMD} --password ${PASSWORD}"
[ "${USE_MDNS}" != "true" ] && CMD="${CMD} --no-mdns"
bashio::log.info "Starting Shelly Dashboard..."
exec ${CMD}
