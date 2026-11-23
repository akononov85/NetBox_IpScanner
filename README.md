# NetBox ICMP Agent

[English version](README.en.md)

Rust-агент для Linux. На каждом запуске он запрашивает у NetBox IPv4-префиксы с непосредственным Scope сайта и тегом со slug `scan`. Nmap обнаруживает узлы за маршрутизатором с помощью ICMP Echo. Агент принимает только результаты `echo-reply`. Отсутствие ответа оставляет состояние IP неизвестным.

После обнаружения узла через ICMP агент проверяет имя через Nmap `smb-os-discovery` (TCP/139 и 445) и читает `sysName.0` через SNMPv1 (UDP/161, community `public`). DNS-запросы отключены. При создании IP имя SMB имеет приоритет, имя SNMP используется при отсутствии имени SMB. Если имя не получено, поле `dns_name` остаётся пустым. Для новых IP агент пишет `Discovered by network scan` в `description`. Счётчики `with_smb` и `with_snmp` показывают число имён по каждому протоколу.

## Как агент работает

1. При каждом запуске агент обращается к NetBox по HTTPS и ищет сайт по точному имени `site_name`.
2. Агент выбирает IPv4-префиксы, у которых Scope указывает непосредственно на этот сайт и есть тег со slug `scan`. Scope региона, группы площадок или Location в это правило не входит. Снятие тега исключает префикс со следующего запуска.
3. Nmap проверяет ICMP Echo, затем запускает SMB-проверку на ответивших узлах. Агент также опрашивает ответившие IP по SNMPv1, до 16 запросов одновременно с тайм-аутом 2 секунды на запрос.
4. Агент проверяет существующие IP в NetBox по паре IP + VRF независимо от маски. При `apply = true` новые адреса создаются как `/32` со статусом `active`. Существующие записи сохраняются, даже если узел перестал отвечать или имя изменилось.
5. `systemd` запускает службу каждый час. Добавление префикса в NetBox не требует отдельных задач в cron или перезапуска таймера.

## Конфигурация

Скопируйте `agent.example.toml` в рабочий конфиг на целевом прокси. Настройки читаются заново при каждом запуске.

| Поле | Назначение |
|---|---|
| `netbox_url` | Базовый HTTPS-адрес NetBox, например `https://netbox.example.org/`. Агент сам добавляет пути API. |
| `token` | Токен целиком, без префиксов `Bearer ` или `Token `. Вносите его в рабочий файл на целевом прокси. |
| `auth_scheme` | `"Bearer"` для v2, `"Token"` для v1. Для создания v2 на сервере NetBox требуется `API_TOKEN_PEPPERS`. |
| `site_name` | Точное имя сайта в NetBox с учётом регистра. Для каждого прокси укажите его площадку. |
| `apply` | `false` для пробного запуска с выводом `would create`, `true` для записи в IPAM с выводом `created`. |
| `max_addresses` | Максимальное число адресов в одном CIDR. По умолчанию 4096, допустимо от 1 до 65536. |
| `scan_timeout_seconds` | Тайм-аут Nmap на префикс. По умолчанию 180 секунд, допустимо от 1 до 3300. |
| `reachable_vrf_ids` | Список числовых ID VRF, достижимых через таблицу маршрутизации прокси. По умолчанию `[]`. Префиксы без VRF доступны независимо от списка. |

Для пробного запуска пользователю токена нужны права просмотра сайтов, префиксов и IP-адресов. Для записи дополнительно нужны право создания IP-адресов и токен с разрешённой записью. Для одинаковых CIDR в разных VRF запускайте агенты в отдельных сетевых контекстах с соответствующими маршрутами.

## Установка на другой прокси

Требуются NetBox 4.2+, Linux с systemd, Nmap в `/usr/bin/nmap` и GNU timeout в `/usr/bin/timeout`. Прокси должен иметь доступ к HTTPS NetBox и маршруты до своих префиксов. Для обнаружения нужен ICMP Echo, а для получения имени должны проходить SMB (TCP/139,445) или SNMP (UDP/161).

Можно использовать готовый бинарник с другого прокси, если совпадает архитектура и совместимы libc и OpenSSL, например на другом Debian 13 x86_64. Установленный бинарник находится в `/usr/local/bin/netbox-icmp-agent`. На целевом Debian установите зависимости от root:

```sh
apt-get update
apt-get install -y --no-install-recommends nmap coreutils ca-certificates libssl3t64
```

Для самостоятельной сборки используйте исходники `Cargo.toml`, `Cargo.lock` и `src/` на Linux, совместимом с целевым прокси. Установите Rust/Cargo (проверено с Rust 1.100.0), `build-essential`, `pkg-config` и `libssl-dev`, затем выполните в каталоге исходников:

```sh
cargo build --release --locked
```

Перенесите бинарник (при сборке он находится в `target/release`), `agent.example.toml` и каталог `systemd/` на прокси. Из каталога с этими файлами выполните от root:

```sh
getent passwd netbox-scan >/dev/null || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin netbox-scan
install -m 0755 netbox-icmp-agent /usr/local/bin/netbox-icmp-agent
install -d -o root -g netbox-scan -m 0750 /etc/netbox-icmp-agent
if [ ! -e /etc/netbox-icmp-agent/agent.toml ]; then
    install -o root -g netbox-scan -m 0640 agent.example.toml /etc/netbox-icmp-agent/agent.toml
fi
install -m 0644 systemd/netbox-icmp-agent.service systemd/netbox-icmp-agent.timer /etc/systemd/system/
systemctl daemon-reload
```

### Первый запуск

1. В `/etc/netbox-icmp-agent/agent.toml` задайте URL, точное имя площадки, токен и схему авторизации. Оставьте `apply = false`.
2. В NetBox выберите один тестовый IPv4-префикс со Scope **Site → имя площадки** и тегом **scan**.
3. Запустите службу и проверьте журнал.

```sh
systemctl start netbox-icmp-agent.service
journalctl -u netbox-icmp-agent.service -n 50 --no-pager
```

В журнале проверьте `site`, `prefixes`, `failed=0`, число `replies` и строки `would create`. Когда результат устраивает, задайте `apply = true`, снова запустите службу и сверьте строки `created` с записями IPAM. Повторный запуск пропустит существующие записи. Для одной площадки и таблицы маршрутизации используйте один экземпляр агента, чтобы избежать параллельного создания дублей.

```sh
systemctl enable --now netbox-icmp-agent.timer
systemctl list-timers netbox-icmp-agent.timer
```

### Файлы на прокси

| Путь | Назначение |
|---|---|
| `/usr/local/bin/netbox-icmp-agent` | Исполняемый файл Rust. |
| `/etc/netbox-icmp-agent/agent.toml` | Настройки и токен, владелец `root:netbox-scan`, права `0640`. |
| `/etc/systemd/system/netbox-icmp-agent.service` | Одноразовый запуск от пользователя `netbox-scan` с `CAP_NET_RAW` для ICMP. Общий тайм-аут 55 минут. |
| `/etc/systemd/system/netbox-icmp-agent.timer` | Почасовой запуск. `Persistent=true` выполняет один пропущенный запуск после простоя. |
| `/etc/netbox-icmp-agent/ca-bundle.pem` | Дополнительный набор сертификатов для TLS. Нужен лишь там, где используется отдельная TLS-настройка службы. |

### Диагностика

- **`prefixes=0`** — проверьте Scope типа Site, точное имя сайта, slug тега `scan` и видимость префиксов для пользователя API.
- **HTTP 401 или 403** — проверьте версию токена, `auth_scheme`, срок действия, ограничения токена по адресу клиента и права пользователя. Если чтение работает, а падает создание, проверьте право добавления IP и разрешение записи у токена.
- **Ошибка TLS** — проверьте цепочку сертификатов, которую отдаёт NetBox. При внутреннем CA установите доверенный сертификат этой организации. Для отдельного набора доверенных сертификатов укажите `SSL_CERT_FILE` в `/etc/systemd/system/netbox-icmp-agent.service.d/tls.conf`. Для другого прокси проверьте TLS отдельно. Предпочтительное исправление для неполной цепочки — настроить её на стороне HTTPS-сервера NetBox.
- **Узел ответил без имени** — проверьте доступность TCP/139,445 и UDP/161 с прокси. SNMP-устройство должно принимать запросы v1 с community `public` и отдавать `sysName.0`.
- **Пауза или откат к отчёту** — остановите таймер командой `systemctl disable --now netbox-icmp-agent.timer` либо верните `apply = false` для следующих запусков.
