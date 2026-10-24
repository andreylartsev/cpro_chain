# cpro_chain

Инструмент для построения/обновления цепочки сертификатов PKI с использованием CryptoPro CSP.

## Назначение
Скрипт `get_chain.sh` рекурсивно обходит цепочку сертификатов от стартового (`secrets/my_cert.cer`):
- извлекает `CRL Distribution Points` и `Authority Information Access` (AIA)
- скачивает недостающие CRL и сертификаты промежуточных/корневых УЦ в `downloaded_chain/`
- при наличии `AIA` переходит к родительскому сертификату и обрабатывает его рекурсивно
- определяет корневой УЦ по совпадению `Subject == Issuer`

## Требования
- Linux
- [CryptoPro CSP](https://www.cryptopro.ru/) с утилитой `certmgr` (по умолчанию `/opt/cprocsp/bin/amd64/certmgr`)
- `curl`, `logger`
- Сетевой доступ к URL из расширений сертификатов

## Структура
```
.
├── get_chain.sh        # основной скрипт
├── secrets/            # исходный сертификат (игнорируется)
├── downloaded_chain/   # скачанные CRL/сертификаты (игнорируются)
└── .gitignore
```

## Настройка
Отредактируйте блок `КОНФИГУРАЦИЯ` в `get_chain.sh` под ваше окружение:
```bash
PROJECT_DIR="/path/to/project"
OUTPUT_DIR="${PROJECT_DIR}/downloaded_chain"
START_CERT="${PROJECT_DIR}/secrets/my_cert.cer"
CERTMGR="/opt/cprocsp/bin/amd64/certmgr"
CURL="/usr/bin/curl"
LOGGER="/usr/bin/logger"
```

Положите стартовый сертификат в `secrets/my_cert.cer`.

## Запуск
```bash
chmod +x get_chain.sh
./get_chain.sh
```

Логи выводятся в консоль и в syslog с тегом `cpro_chain_downloader`.

## Примечания
- Скрипт парсит русскоязычный вывод `certmgr -list -file` (ключевые строки: `URL списка отзыва`, `URL сертификата УЦ`, `Субъект`, `Издатель`). Для однозначного парсинга в скрипте принудительно выставляется `LANG=ru_RU.UTF-8`.
- Файлы скачиваются во временный `.tmp` в `downloaded_chain/`, после чего переименовываются по **SHA-1 отпечатку**: `<sha1>.crt` для сертификатов, `<sha1>.crl` для CRL.
- **CRL** при наличии `ETag`/`Last-Modified` скачиваются условно (`If-None-Match`/`If-Modified-Since`), при ответе `304 Not Modified` пропускаются; если заголовки отсутствуют — скачиваются полностью. **Родительские сертификаты УЦ** из AIA при повторном запуске не перекачиваются, если файл с таким отпечатком уже существует.
- Если поле AIA отсутствует и `Subject != Issuer` — цепочка оборвана (выводится предупреждение).

## Добавление в crontab (автоматический запуск)

Для периодического обновления цепочки можно добавить задачу в crontab. Скрипт сам пишет логи в syslog и в консоль.

1. Откройте crontab для редактирования:
```bash
crontab -e
```

2. Добавьте запись. Например, запуск каждый день в 03:00:
```cron
0 3 * * * /bin/bash /path/to/project/get_chain.sh
```

Или запуск каждый час:
```cron
0 * * * * /bin/bash /path/to/project/get_chain.sh
```

**Рекомендации:**
- Укажите **абсолютный путь** к `get_chain.sh` и при необходимости поправьте `PROJECT_DIR` в самом скрипте (либо экспортируйте переменные окружения в crontab).
- Убедитесь, что у пользователя, под которым запускается cron, есть доступ к `certmgr`, `curl`, сетевые права и права на запись в `downloaded_chain/`.
- Логи доступны через `journalctl -t cpro_chain_downloader` или в системном syslog.

## Пример конфигурации для syslog-ng

Если используется `syslog-ng`, можно добавить отдельный файл (например, `/etc/syslog-ng/conf.d/cpro_chain.conf`):

```conf
# Фильтр по тегу скрипта
filter f_cpro_chain {
    program("cpro_chain_downloader");
};

# Отдельный файл логов
destination d_cpro_chain {
    file("/var/log/cpro_chain_downloader.log" perm(0640));
};

# Правило маршрутизации
log {
    source(s_sys);
    filter(f_cpro_chain);
    destination(d_cpro_chain);
};
```

После добавления перезагрузите syslog-ng: `systemctl reload syslog-ng`.
