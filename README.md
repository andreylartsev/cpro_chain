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
- Скрипт парсит русскоязычный вывод `certmgr -list -file` (ключевые строки: `URL списка отзыва`, `URL сертификата УЦ`, `Субъект`, `Издатель`).
- Скачанные файлы сохраняются в `downloaded_chain/` с именем из URL. При повторном запуске уже существующие файлы не перекачиваются.
- Если поле AIA отсутствует и `Subject != Issuer` — цепочка оборвана (выводится предупреждение).
