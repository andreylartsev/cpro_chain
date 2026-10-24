#!/bin/bash

# ==============================================================================
# КОНФИГУРАЦИЯ
# ==============================================================================
# Определяем корневую директорию проекта относительно расположения скрипта
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-${SCRIPT_DIR}}"
OUTPUT_DIR="${OUTPUT_DIR:-${PROJECT_DIR}/downloaded_chain}"
START_CERT="${START_CERT:-${PROJECT_DIR}/secrets/my_cert.cer}"

# Пути к исполняемым файлам
CERTMGR="${CERTMGR:-/opt/cprocsp/bin/amd64/certmgr}"
CURL="${CURL:-/usr/bin/curl}"
LOGGER="${LOGGER:-/usr/bin/logger}"

# Настройки логирования в syslog (тег и приоритет)
SYSLOG_TAG="${SYSLOG_TAG:-cpro_chain_downloader}"
SYSLOG_FACILITY="${SYSLOG_FACILITY:-user.notice}"

# Массив для отслеживания посещённых сертификатов (защита от циклов)
declare -A VISITED_CERTS=()
# ==============================================================================

mkdir -p "$OUTPUT_DIR" || {
    echo "Ошибка: Не удалось создать каталог $OUTPUT_DIR" >&2
    exit 1
}

# Функция отправки логов в syslog и консоль одновременно
log_message() {
    local msg="$1"
    # Вывод в консоль для ручного запуска
    echo -e "$msg"
    # Отправка в системный лог (syslog) без ANSI-цветов и лишних символов
    local clean_msg
    clean_msg=$(echo "$msg" | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    if [ -x "$LOGGER" ]; then
        "$LOGGER" -p "$SYSLOG_FACILITY" -t "$SYSLOG_TAG" "$clean_msg" 2>/dev/null || true
    fi
}

# Извлечение значения по метке из вывода certmgr (русский язык)
extract_value() {
    local cert_info="$1"
    local label="$2"
    # Ищем строку с меткой и берём всё после первого ": "
    echo "$cert_info" | grep -m 1 "$label" | awk -F': ' '{if (NF>=2) {out=$2; for(i=3;i<=NF;i++) out=out": "$i; print out}}' | sed 's/[[:space:]]*$//' | tr -d '\r'
}

process_certificate() {
    local cert_file="$1"
    local cert_name
    cert_name=$(basename "$cert_file")
    
    # Защита от циклов - используем абсолютный путь как ключ
    local cert_key
    cert_key=$(readlink -f "$cert_file" 2>/dev/null || echo "$cert_file")
    if [[ -n "${VISITED_CERTS[$cert_key]:-}" ]]; then
        log_message "Пропуск: Циклическая ссылка обнаружена для $cert_name"
        return 0
    fi
    VISITED_CERTS["$cert_key"]=1
    
    log_message "Разбираем сертификат: $cert_name"
    
    # Проверка существования файла
    if [ ! -f "$cert_file" ] || [ ! -s "$cert_file" ]; then
        log_message "Ошибка: Файл сертификата не найден или пуст: $cert_name"
        return 1
    fi
    
    # Читаем данные через КриптоПро certmgr
    if [ ! -x "$CERTMGR" ]; then
        log_message "Ошибка: Утилита certmgr не найдена или не исполняема: $CERTMGR"
        return 1
    fi
    
    local cert_info
    cert_info=$("$CERTMGR" -list -file "$cert_file" 2>/dev/null)
    if [ $? -ne 0 ] || [ -z "$cert_info" ]; then
        log_message "Ошибка: Не удалось прочитать файл сертификата через КриптоПро: $cert_name"
        return 1
    fi

    # 1. Извлекаем и качаем CRL
    local crl_url
    crl_url=$(extract_value "$cert_info" "URL списка отзыва")
    if [ -n "$crl_url" ]; then
        local crl_name
        crl_name=$(basename "$crl_url")
        # Если имя пустое или содержит недопустимые символы, генерируем на основе хеша
        if [ -z "$crl_name" ] || [ "$crl_name" = "/" ]; then
            crl_name="crl_$(echo -n "$crl_url" | md5sum | awk '{print $1}').crl"
        fi
        local crl_path="$OUTPUT_DIR/$crl_name"
        if [ ! -f "$crl_path" ] || [ ! -s "$crl_path" ]; then
            log_message "Скачивание CRL: $crl_url"
            if [ -x "$CURL" ]; then
                if $CURL -s -f -L -m 30 "$crl_url" -o "$crl_path"; then
                    if [ ! -s "$crl_path" ]; then
                        log_message "Предупреждение: Скачанный CRL пуст: $crl_name"
                        rm -f "$crl_path"
                    else
                        log_message "Успешно скачан CRL: $crl_name"
                    fi
                else
                    log_message "Предупреждение: Не удалось скачать CRL: $crl_url"
                    rm -f "$crl_path"
                fi
            else
                log_message "Ошибка: Утилита curl не найдена или не исполняема: $CURL"
            fi
        else
            log_message "Пропуск CRL. Уже скачан: $crl_name"
        fi
    fi

    # 2. Извлекаем и качаем родительский УЦ (AIA)
    local parent_url
    parent_url=$(extract_value "$cert_info" "URL сертификата УЦ")
    if [ -n "$parent_url" ]; then
        local parent_name
        parent_name=$(basename "$parent_url")
        if [ -z "$parent_name" ] || [ "$parent_name" = "/" ]; then
            parent_name="ca_$(echo -n "$parent_url" | md5sum | awk '{print $1}').crt"
        fi
        local parent_path="$OUTPUT_DIR/$parent_name"
        
        if [ ! -f "$parent_path" ] || [ ! -s "$parent_path" ]; then
            log_message "Скачивание УЦ: $parent_url"
            if [ -x "$CURL" ]; then
                if $CURL -s -f -L -m 30 "$parent_url" -o "$parent_path"; then
                    if [ ! -s "$parent_path" ]; then
                        log_message "Предупреждение: Скачанный сертификат УЦ пуст: $parent_name"
                        rm -f "$parent_path"
                    else
                        log_message "Успешно скачан УЦ: $parent_name"
                    fi
                else
                    log_message "Предупреждение: Не удалось скачать сертификат УЦ: $parent_url"
                    rm -f "$parent_path"
                fi
            else
                log_message "Ошибка: Утилита curl не найдена или не исполняема: $CURL"
            fi
        else
            log_message "Пропуск УЦ. Уже скачан: $parent_name"
        fi
        
        # Рекурсивный вызов для следующего уровня только если файл существует и не пуст
        if [ -f "$parent_path" ] && [ -s "$parent_path" ]; then
            process_certificate "$parent_path"
        else
            log_message "Предупреждение: Пропуск рекурсивной обработки - родительский сертификат недоступен"
        fi
    else
        # 3. Проверяем на Корневой УЦ
        local subject
        local issuer
        subject=$(extract_value "$cert_info" "Субъект")
        issuer=$(extract_value "$cert_info" "Издатель")
        
        # Нормализуем пробелы для сравнения
        subject_clean=$(echo "$subject" | sed 's/[[:space:]]\+/ /g' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        issuer_clean=$(echo "$issuer" | sed 's/[[:space:]]\+/ /g' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
        if [ -n "$subject_clean" ] && [ "$subject_clean" = "$issuer_clean" ]; then
            log_message "Подтверждено: Это Корневой УЦ (сертификат самоподписанный, Subject == Issuer)."
        elif [ -z "$subject_clean" ] || [ -z "$issuer_clean" ]; then
            log_message "Внимание! Не удалось определить Субъект/Издатель. Цепочка может быть неполной."
        else
            log_message "Внимание! Цепочка оборвалась. Поле AIA отсутствует, но сертификат НЕ самоподписанный. Издатель: $issuer_clean, Субъект: $subject_clean"
        fi
    fi
}

# Точка входа
log_message "=== Старт проверки и обновления цепочки PKI ==="
log_message "Проект: $PROJECT_DIR"
log_message "Выходной каталог: $OUTPUT_DIR"
log_message "Стартовый сертификат: $START_CERT"

if [ -f "$START_CERT" ] && [ -s "$START_CERT" ]; then
    process_certificate "$START_CERT"
    log_message "Готово. Процесс завершен успешно."
else
    log_message "Ошибка: Стартовый файл $START_CERT не найден или пуст!"
    exit 1
fi
