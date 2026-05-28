# Changelog

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
