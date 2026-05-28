# Changelog

## 1.4.0

- **Home Assistant Ingress**: dodatek pojawia się w bocznym pasku HA i otwiera się w głównym ekranie (bez konieczności przechodzenia na osobny port)
- `config.yaml`: `ingress: true`, `ingress_port: 5000`, `panel_title`, `panel_icon`, `panel_admin: false`
- Front-end: wszystkie zapytania do `/api/*` przechodzą teraz przez dynamiczny `BASE` (działa zarówno przez Ingress jak i po bezpośrednim wejściu na port 5000)
- Zachowano także bezpośredni dostęp przez port `5000` (do użycia poza HA)

## 1.3.0

- Dashboard: dodano wiersz **Ethernet** na karcie urządzenia
- Status połączenia LAN pobierany automatycznie z `Shelly.GetStatus` (`eth.ip`) dla Gen2+
- Wyświetlanie IP ethernetowego oraz odznaki: 🔌 połączony / odłączony / brak / N/A (Gen1)
- Dodano też SSID WiFi w danych urządzenia

## 1.2.0

- Dashboard: dodano pole **Hostname** na karcie urządzenia (pobierane automatycznie z urządzenia: Gen2+ przez `/shelly` → `id` / `Shelly.GetConfig` → `sys.device.hostname`, Gen1 przez `/settings` → `device.hostname`)
- Wyszukiwarka obejmuje teraz również hostname

## 1.1.0

- Przeprojektowany interfejs web dashboardu (nowoczesny wygląd, cienie, zaokrąglenia, hover na kartach)
- Sticky toolbar z logo i pogrupowanymi akcjami
- Przełącznik motywu jasny/ciemny (zapamiętywany w `localStorage`)
- Wyszukiwarka urządzeń po nazwie / IP / modelu
- Filtry: Wszystkie / Online / Offline / Aktualizacje
- Statusowe odznaki na kartach: Online / Offline / Update / Aktualne
- Wskaźnik siły sygnału WiFi i czytelny uptime (np. `2d 5h 13m`)
- Powiadomienia toast dla akcji (odkrywanie, odświeżanie, przełączanie)
- Przycisk otwierający natywny panel Shelly w nowej karcie
- Obsługa Enter w polu dodawania urządzenia
- Naprawiono błąd budowania obrazu (`build.yaml` przypięty do `3.12-alpine3.20`)
- Dockerfile: `pip3 install` z `--break-system-packages` (PEP 668)
- Schemat opcji: pola tekstowe oznaczone jako opcjonalne (`str?`, `password?`), zakresy dla wartości liczbowych

## 1.0.0

- Pierwsza wersja dodatku Home Assistant
- Dashboard Flask
- Monitoring Shelly Gen1 i Gen2+
- Sprawdzanie firmware
- REST API
