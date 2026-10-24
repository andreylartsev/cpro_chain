#!/bin/bash

# ==============================================================================
# КОНФИГУРАЦИЯ
# ==============================================================================
# Абсолютный путь к папке проекта (cron запускает скрипты из домашней папки)
PROJECT_DIR="/home/avl/WinProjects/cpro_chain"
OUTPUT_DIR="${PROJECT_DIR}/downloaded_chain"
START_CERT="${PROJECT_DIR}/secrets/my_cert.cer"

# Пути к исполняемым файлам
CERTMGR="/opt/cprocsp/bin/amd64/certmgr"
CURL="/usr/bin/curl"
LOGGER="/usr/bin/logger"

# Настройки логирования в syslog (тег и приоритет)
SYSLOG_TAG="cpro_chain_downloader"
SYSLOG_FACILITY="user.notice"
# ==============================================================================

mkdir -p "$OUTPUT_DIR"

# Функция отправки логов в syslog и консоль одновременно
log_message() {
    local msg="$1"
    # Вывод в консоль для ручного запуска
    echo -e "$msg"
    # Отправка в системный лог (syslog) без ANSI-цветов и лишних символов
    clean_msg=$(echo "$msg" | sed 's/^[ \t]*//;s/\[ //;s/ \]//')
    $LOGGER -p "$SYSLOG_FACILITY" -t "$SYSLOG_TAG" "$clean_msg"
}

process_certificate() {
    local cert_file="$1"
    local cert_name=$(basename "$cert_file")
    
    log_message "Разбираем сертификат: $cert_name"
    
    # Читаем данные через КриптоПро certmgr
    local cert_info=$($CERTMGR -list -file "$cert_file" 2>/dev/null)
    if [ $? -ne 0 ] || [ -z "$cert_info" ]; then
        log_message "Ошибка: Не удалось прочитать файл сертификата через КриптоПро: $cert_name"
        return 1
    fi

    # 1. Извлекаем и качаем CRL
    local crl_url=$(echo "$cert_info" | grep "URL списка отзыва" | awk -F': ' '{print $2}' | tr -d '\r')
    if [ ! -z "$crl_url" ]; then
        local crl_name=$(basename "$crl_url")
        if [ ! -f "$OUTPUT_DIR/$crl_name" ]; then
            log_message "Скачивание CRL: $crl_url"
            $CURL -s -m 10 "$crl_url" -o "$OUTPUT_DIR/$crl_name"
        else
            log_message "Пропуск CRL. Уже скачан: $crl_name"
        fi
    fi

    # 2. Извлекаем и качаем родительский УЦ (AIA)
    local parent_url=$(echo "$cert_info" | grep "URL сертификата УЦ" | awk -F': ' '{print $2}' | tr -d '\r')
    if [ ! -z "$parent_url" ]; then
        local parent_name=$(basename "$parent_url")
        local parent_path="$OUTPUT_DIR/$parent_name"
        
        if [ ! -f "$parent_path" ]; then
            log_message "Скачивание УЦ: $parent_url"
            $CURL -s -m 10 "$parent_url" -o "$parent_path"
        else
            log_message "Пропуск УЦ. Уже скачан: $parent_name"
        fi
        
        # Рекурсивный вызов для следующего уровня
        process_certificate "$parent_path"
    else
        # 3. Проверяем на Корневой УЦ
        local subject=$(echo "$cert_info" | grep "Субъект" | awk -F': ' '{print $2}')
        local issuer=$(echo "$cert_info" | grep "Издатель" | awk -F': ' '{print $2}')
        
        if [ "$subject" == "$issuer" ]; then
            log_message "Подтверждено: Это Корневой УЦ (сертификат самоподписанный, Subject == Issuer)."
        else
            log_message "Внимание! Цепочка оборвалась. Поле AIA отсутствует, но сертификат НЕ самоподписанный. Издатель: $issuer, Субъект: $subject"
        fi
    fi
}

# Точка входа
log_message "=== Старт проверки и обновления цепочки PKI ==="

if [ -f "$START_CERT" ]; then
    process_certificate "$START_CERT"
    log_message "Готово. Процесс завершен успешно."
else
    log_message "Ошибка: Стартовый файл $START_CERT не найден!"
    exit 1
fi
