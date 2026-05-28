# Dokumentacja Shelly Dashboard

## Start

Po instalacji ustaw przynajmniej jedną z opcji:

```yaml
devices: "192.168.1.10,192.168.1.11"
```

lub:

```yaml
network: "192.168.1.0/24"
```

Możesz też zostawić puste i użyć mDNS, jeśli multicast działa w Twojej sieci.

## Dostęp

Po uruchomieniu kliknij **Open Web UI** w dodatku albo wejdź na port 5000, jeśli port został wystawiony.

## REST API

- `GET /api/devices`
- `GET /api/summary`
- `POST /api/refresh`
- `POST /api/discover`
- `POST /api/firmware/check`
- `POST /api/device/<ip>/firmware/check`
- `POST /api/device/<ip>/relay/<id>/on`
- `POST /api/device/<ip>/relay/<id>/off`
- `POST /api/device/<ip>/relay/<id>/toggle`
