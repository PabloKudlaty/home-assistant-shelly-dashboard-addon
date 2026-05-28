# Shelly Dashboard

Webowy dashboard do lokalnego monitorowania urządzeń Shelly, sprawdzania firmware i sterowania przekaźnikami.

## Funkcje

- Odkrywanie Shelly przez mDNS i/lub skan podsieci
- Obsługa Gen1 oraz Gen2/Gen3/Gen4
- Status urządzeń, WiFi, moc, energia, uptime
- Sprawdzanie firmware: Gen1 `/ota/check` + `/ota` + `/status.update`, Gen2+ `Shelly.CheckForUpdate`
- Prosty dashboard webowy
- REST API dla Home Assistant

## Konfiguracja

- `devices` — opcjonalna lista IP po przecinku
- `network` — opcjonalna podsieć, np. `192.168.1.0/24`
- `refresh` — interwał odświeżania w sekundach
- `timeout` — timeout HTTP do urządzeń Shelly
- `user` / `password` — dane auth dla urządzeń Shelly
