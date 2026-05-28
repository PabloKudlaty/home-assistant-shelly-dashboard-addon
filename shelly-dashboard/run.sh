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

if [ -n "${DEVICES}" ]; then
  CMD="${CMD} --devices ${DEVICES}"
fi

if [ -n "${NETWORK}" ]; then
  CMD="${CMD} --network ${NETWORK}"
fi

if [ -n "${USER_NAME}" ]; then
  CMD="${CMD} --user ${USER_NAME}"
fi

if [ -n "${PASSWORD}" ]; then
  CMD="${CMD} --password ${PASSWORD}"
fi

if [ "${USE_MDNS}" != "true" ]; then
  CMD="${CMD} --no-mdns"
fi

bashio::log.info "Starting Shelly Dashboard..."
bashio::log.info "Devices: ${DEVICES:-auto}"
bashio::log.info "Network: ${NETWORK:-not configured}"
bashio::log.info "Refresh interval: ${REFRESH}s"

exec ${CMD}
