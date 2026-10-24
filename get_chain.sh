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

# Язык вывода для однозначного парсинга русскоязычного вывода certmgr
# Обязателен для корректного парсинга: URL списка отзыва, URL сертификата УЦ, Субъект, Издатель
export LANG="${CERTMGR_LANG:-ru_RU.UTF-8}"
export LC_ALL="${CERTMGR_LC_ALL:-ru_RU.UTF-8}"
export LC_MESSAGES="${CERTMGR_LC_MESSAGES:-ru_RU.UTF-8}"

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

# Получить SHA-1 отпечаток сертификата в нижнем регистре без двоеточий
get_cert_fingerprint() {
    local f="$1"
    [ -s "$f" ] || return 1
    local fp
    fp=$(openssl x509 -in "$f" -noout -fingerprint -sha1 2>/dev/null | sed 's/^.*=//' | tr -d ':' | tr '[:upper:]' '[:lower:]')
    [ -n "$fp" ] && echo "$fp"
}

# Получить CN из сертификата
get_cert_cn() {
    local f="$1"
    [ -s "$f" ] || return 1
    local cn
    cn=$(openssl x509 -in "$f" -noout -subject -nameopt oneline 2>/dev/null | sed -n 's/.*CN[[:space:]]*=[[:space:]]*\([^,/]*\).*/\1/p')
    [ -z "$cn" ] && cn=$(openssl x509 -in "$f" -noout -subject -nameopt multiline 2>/dev/null | grep -m1 'CN' | awk -F'= ' '{print $2}' | sed 's/[[:space:]]*$//')
    [ -n "$cn" ] && echo "$cn"
}

# Получить SHA-1 отпечаток CRL в нижнем регистре без двоеточий
get_crl_fingerprint() {
    local f="$1"
    [ -s "$f" ] || return 1
    local fp
    fp=$(openssl crl -in "$f" -noout -fingerprint -sha1 2>/dev/null | sed 's/^.*=//' | tr -d ':' | tr '[:upper:]' '[:lower:]')
    [ -n "$fp" ] && echo "$fp"
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
    
    local cert_cn_cur
    cert_cn_cur=$(get_cert_cn "$cert_file")
    if [ -n "$cert_cn_cur" ]; then
        log_message "Разбираем сертификат: $cert_name ($cert_cn_cur)"
    else
        log_message "Разбираем сертификат: $cert_name"
    fi
    
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
    # CRL может обновляться, поэтому при наличии ETag/Last-Modified пробуем условное скачивание
    local crl_url
    crl_url=$(extract_value "$cert_info" "URL списка отзыва")
    if [ -n "$crl_url" ]; then
        log_message "Проверка/обновление CRL: $crl_url"
        if [ -x "$CURL" ]; then
            local crl_tmp="$OUTPUT_DIR/.crl.$$.$RANDOM.tmp"
            local crl_headers="$OUTPUT_DIR/.crl.$$.$RANDOM.headers"
            # Сначала пробуем HEAD для получения ETag/Last-Modified
            local crl_etag crl_lastmod
            $CURL -s -I -L -m 15 "$crl_url" -o "$crl_headers" 2>/dev/null
            crl_etag=$(grep -i '^ETag:' "$crl_headers" 2>/dev/null | tail -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r' | sed 's/[[:space:]]*$//')
            crl_lastmod=$(grep -i '^Last-Modified:' "$crl_headers" 2>/dev/null | tail -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r' | sed 's/[[:space:]]*$//')
            rm -f "$crl_headers"

            local curl_opts=(-s -f -L -m 30)
            [ -n "$crl_etag" ] && curl_opts+=(-H "If-None-Match: $crl_etag")
            [ -n "$crl_lastmod" ] && [ -z "$crl_etag" ] && curl_opts+=(-H "If-Modified-Since: $crl_lastmod")

            local http_code
            http_code=$($CURL -w '%{http_code}' "${curl_opts[@]}" -o "$crl_tmp" "$crl_url" 2>/dev/null)
            if [ "$http_code" = "304" ]; then
                log_message "CRL не изменился (304 Not Modified), пропуск скачивания"
                rm -f "$crl_tmp"
            elif [ "$http_code" = "200" ] || [ -z "$http_code" ] && [ -s "$crl_tmp" ]; then
                if [ ! -s "$crl_tmp" ]; then
                    log_message "Предупреждение: Скачанный CRL пуст"
                    rm -f "$crl_tmp"
                else
                    local crl_fp
                    crl_fp=$(get_crl_fingerprint "$crl_tmp")
                    if [ -n "$crl_fp" ]; then
                        local crl_final="$OUTPUT_DIR/${crl_fp}.crl"
                        mv -f "$crl_tmp" "$crl_final"
                        log_message "Успешно обновлён CRL: ${crl_fp}.crl"
                    else
                        log_message "Предупреждение: Не удалось определить отпечаток CRL, файл оставлен как .tmp: $(basename "$crl_tmp")"
                    fi
                fi
            else
                log_message "Предупреждение: Не удалось скачать CRL: $crl_url (HTTP $http_code)"
                rm -f "$crl_tmp"
            fi
        else
            log_message "Ошибка: Утилита curl не найдена или не исполняема: $CURL"
        fi
    fi

    # 2. Извлекаем и качаем родительский УЦ (AIA)
    local parent_url
    parent_url=$(extract_value "$cert_info" "URL сертификата УЦ")
    if [ -n "$parent_url" ]; then
        log_message "Скачивание УЦ: $parent_url"
        if [ -x "$CURL" ]; then
            local parent_tmp="$OUTPUT_DIR/.ca.$$.$RANDOM.tmp"
            if $CURL -s -f -L -m 30 "$parent_url" -o "$parent_tmp"; then
                if [ ! -s "$parent_tmp" ]; then
                    log_message "Предупреждение: Скачанный сертификат УЦ пуст"
                    rm -f "$parent_tmp"
                else
                    local parent_fp
                    parent_fp=$(get_cert_fingerprint "$parent_tmp")
                    if [ -n "$parent_fp" ]; then
                        local parent_path="$OUTPUT_DIR/${parent_fp}.crt"
                        if [ -f "$parent_path" ] && [ -s "$parent_path" ]; then
                            local parent_cn
                            parent_cn=$(get_cert_cn "$parent_path")
                            if [ -n "$parent_cn" ]; then
                                log_message "Пропуск УЦ. Уже скачан по отпечатку: ${parent_fp}.crt ($parent_cn)"
                            else
                                log_message "Пропуск УЦ. Уже скачан по отпечатку: ${parent_fp}.crt"
                            fi
                            rm -f "$parent_tmp"
                        else
                            mv -f "$parent_tmp" "$parent_path"
                            local parent_cn
                            parent_cn=$(get_cert_cn "$parent_path")
                            if [ -n "$parent_cn" ]; then
                                log_message "Успешно скачан УЦ: ${parent_fp}.crt ($parent_cn)"
                            else
                                log_message "Успешно скачан УЦ: ${parent_fp}.crt"
                            fi
                        fi
                        # Рекурсивный вызов для следующего уровня
                        if [ -f "$parent_path" ] && [ -s "$parent_path" ]; then
                            process_certificate "$parent_path"
                        else
                            log_message "Предупреждение: Пропуск рекурсивной обработки - родительский сертификат недоступен"
                        fi
                    else
                        log_message "Предупреждение: Не удалось определить отпечаток сертификата УЦ, файл оставлен как .tmp: $(basename "$parent_tmp")"
                    fi
                fi
            else
                log_message "Предупреждение: Не удалось скачать сертификат УЦ: $parent_url"
                rm -f "$parent_tmp"
            fi
        else
            log_message "Ошибка: Утилита curl не найдена или не исполняема: $CURL"
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
