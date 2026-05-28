# Changelog

## 1.10.0

- Pobieranie **nazw kanałów** zdefiniowanych przez użytkownika (Switch/Input/Cover/Light)
- Gen2+: z `Shelly.GetConfig` (pola `switch:N.name`, `input:N.name`, itd.)
- Gen1: z `/settings` (`relays[i].name`)
- Nazwa kanału wyświetlana w karcie obok przycisku ON/OFF (z numerem kanału w nawiasie)
- API: pole `channel_names` na urządzeniu + `name` w obiekcie switcha

## 1.9.3

- Hotfix: naprawiono uszkodzony blok Gen1 w `query()` (SyntaxError uniemożliwiał start dodatku po 1.9.2)

## 1.9.2

- Pobieranie nazwy urządzenia bardziej odporne: Gen2+ używa `Shelly.GetConfig` → fallback `Sys.GetConfig`
- Gen1: nazwa z `/settings` (pole `name`)
- Gdy brak nazwy → fallback hostname → model (zamiast od razu na model)

## 1.9.1

- Nagłówek karty urządzenia: **nazwa zdefiniowana przez użytkownika** (z `Shelly.GetConfig` / `/settings` → `name`)
- Hostname przeniesiony do podtytułu (obok IP i Gen)
- Fallback: gdy brak nazwy → hostname → model
- Sortowanie również po nazwie użytkownika

## 1.9.0

- Górna belka statystyk: kompaktowa, **wszystkie 10 kafelków w jednej linii** (poziomy układ, ikona obok wartości)
- Na wąskich ekranach (<900 px) automatyczne zawijanie do 3 kolumn
- **Hostname jako tytuł karty urządzenia**; model i IP przeniesione do linii pod tytułem
- Sortowanie listy urządzeń teraz po hostname (z fallbackiem do device_name/IP)
- Skrócone etykiety: „Moc", „Kondycja"

## 1.8.0

- Dodano **wskaźnik kondycji urządzenia (Health Score 0–100)** wyliczany na podstawie ważonej oceny:
  - Online (35), Web UI (15), Firmware aktualny (15), Siła WiFi (10), Łączność WiFi/Eth (10), Brak błędów API (5), Uptime >5 min (5), Czas odpowiedzi Web <500 ms (5)
- Próg kolorów: **≥85** zielony / **60–84** żółty / **<60** czerwony
- Kolorowy **pasek kondycji** na każdej karcie + lista pigułek z wykrytymi problemami (offline, słaby WiFi, dostępny FW, timeout Web itd.)
- Nowy kafelek **Średnia kondycja** (%) i **Problemy** (liczba urządzeń poniżej „good")
- Nowy filtr **🚨 Problemy** w pasku chipów
- Pełne tłumaczenia PL/EN dla wszystkich nowych etykiet i problemów

## 1.7.1

- Naprawiono błędny komunikat toast podczas testu Web (poprzednio pokazywał „Sprawdzam FW...")
- Dodano oddzielny klucz tłumaczenia `msg_check_web` (PL/EN)

## 1.7.0

- Dodano **kontrolę dostępności panelu Web** każdego urządzenia (sprawdzanie `GET http://<ip>/`)
- Nowy wiersz **Web UI** na kartach: ✅ OK / ⏱ timeout / ❌ błąd / 🔐 wymaga logowania, z kodem HTTP i czasem odpowiedzi (ms)
- Dwa nowe kafelki statystyk: **Web OK** i **Web błąd**
- Przycisk akcji **🌐 Test Web** dla pojedynczego urządzenia + endpoint `POST /api/device/<ip>/web/check`
- Test wykonywany automatycznie przy każdym odświeżeniu (`refresh`)

## 1.6.0

- Dodano **trzy tryby widoku** urządzeń przełączane w pasku narzędziowym:
  - ▣ **Large** — domyślne duże karty (jak dotychczas)
  - ▦ **Small** — mała siatka, kompaktowe karty
  - ☰ **List** — widok listy (jeden wiersz na urządzenie z najważniejszymi danymi)
- Wybrany widok zapamiętywany w `localStorage` (`view`)

## 1.5.1

- Naprawiono brakujący przełącznik języka w pasku narzędziowym (selektor `🌐 Auto / 🇵🇱 Polski / 🇬🇧 English`)
- Dodano atrybuty `data-i18n` / `data-i18n-ph` do wszystkich etykiet, placeholderów i chipów filtrów — teraz `applyI18n()` faktycznie podmienia teksty

## 1.5.0

- Added **English** UI translation alongside Polish
- Language selector in the toolbar: **Auto / Polski / English** (auto-detected from browser `navigator.language`)
- Choice persisted in `localStorage` (`lang` key)
- All labels, placeholders, badges, toasts and stats are translated
- Dynamic `<html lang>` attribute updated on language change

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
