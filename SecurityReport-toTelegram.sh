#!/bin/bash

# =============================================
# تنظیمات اصلی
# =============================================
TELEGRAM_BOT_TOKEN="5054947489:AAFSNuI5JP0MhywlkZQIlePqubUpfVFhH9Q"
TELEGRAM_CHAT_ID="59941862"
CONSOLE_EMAIL="kitzone.ir@gmail.com"
LOG_FILE="/var/log/crowdsec_reports.log"

# =============================================
# توابع
# =============================================

install_prerequisites() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local missing_tools=()

    command -v curl &>/dev/null || missing_tools+=("curl")
    command -v jq &>/dev/null || missing_tools+=("jq")
    command -v cscli &>/dev/null || missing_tools+=("crowdsec")

    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo "[$timestamp] ℹ️ نصب پیش‌نیازها: ${missing_tools[*]}" | tee -a "$LOG_FILE"
        apt update -y >> "$LOG_FILE" 2>&1
        apt install -y "${missing_tools[@]}" >> "$LOG_FILE" 2>&1
        if [ $? -eq 0 ]; then
            echo "[$timestamp] ✅ پیش‌نیازها نصب شدند" | tee -a "$LOG_FILE"
        else
            echo "[$timestamp] ❌ خطا در نصب پیش‌نیازها" | tee -a "$LOG_FILE"
            return 1
        fi
    fi
    return 0
}

send_telegram() {
    local message="$1"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    local response=$(curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TELEGRAM_CHAT_ID" \
        -d "text=$message" \
        -d "parse_mode=HTML" 2>&1)

    if echo "$response" | grep -q '"ok":true'; then
        echo "[$timestamp] ✅ ارسال موفق" | tee -a "$LOG_FILE"
        return 0
    else
        echo "[$timestamp] ❌ خطا: $response" | tee -a "$LOG_FILE"
        return 1
    fi
}

generate_security_report() {
    install_prerequisites || return 1

    # حملات 24 ساعت اخیر
    local attacks=$(sudo cscli alerts list --since 24h 2>/dev/null | grep -v "No active alerts" || echo "هیچ حمله‌ای یافت نشد")
    if [ "$attacks" == "هیچ حمله‌ای یافت نشد" ]; then
        local attacks_report="└─ هیچ حمله‌ای یافت نشد"
    else
        local attacks_report=$(echo "$attacks" | awk '
            NR>1 { 
                printf("├─ <b>سناریو: %s</b>\n│  ├─ IP: %s\n│  ├─ زمان: %s\n│  └─ کشور: %s\n", $1, $2, $3, $4) 
            }' | sed '$s/├─/└─/')
    fi

    # IPهای مسدود شده
    local bans=$(sudo cscli decisions list 2>/dev/null | grep -v "No active decisions" || echo "هیچ IP مسدودی یافت نشد")
    if [ "$bans" == "هیچ IP مسدودی یافت نشد" ]; then
        local bans_report="└─ هیچ IP مسدودی یافت نشد"
    else
        local bans_report=$(echo "$bans" | awk '
            NR>1 { 
                printf("├─ <b>IP: %s</b>\n│  ├─ علت: %s\n│  ├─ مدت: %s\n│  └─ کشور: %s\n", $1, $2, $3, $4) 
            }' | sed '$s/├─/└─/')
    fi

    # متریکس: لاگ‌ها
    local log_metrics=$(sudo cscli metrics 2>/dev/null | awk -F'│' '
        /file:\/var\/log/ { 
            gsub(/^[ \t]+|[ \t]+$/, "", $1); 
            gsub(/^[ \t]+|[ \t]+$/, "", $2); 
            gsub(/^[ \t]+|[ \t]+$/, "", $3); 
            gsub(/^[ \t]+|[ \t]+$/, "", $4); 
            if ($2 ~ /^[0-9-]+$/) { 
                printf("├─ <b>%s</b>\n│  ├─ خوانده‌شده: %s\n│  ├─ پردازش‌شده: %s\n│  └─ پردازش‌نشده: %s\n", $1, $2, $3, $4) 
            } 
        }
    ' | sed '$s/├─/└─/')

    # متریکس: دلایل مسدودسازی
    local ban_reasons=$(sudo cscli metrics 2>/dev/null | awk -F'│' '
        /Reason/ { getline; while ($0 ~ /\|/) { 
            gsub(/^[ \t]+|[ \t]+$/, "", $2); 
            gsub(/^[ \t]+|[ \t]+$/, "", $3); 
            gsub(/^[ \t]+|[ \t]+$/, "", $4); 
            gsub(/^[ \t]+|[ \t]+$/, "", $5); 
            if ($5 ~ /^[0-9]+$/) { 
                printf("├─ <b>%s</b>\n│  ├─ منبع: %s\n│  ├─ اقدام: %s\n│  └─ تعداد: %s\n", $2, $3, $4, $5) 
            }; getline 
        }}
    ' | sed '$s/├─/└─/')

    # متریکس: درخواست‌های API
    local api_metrics=$(sudo cscli metrics 2>/dev/null | awk -F'│' '
        /Route.*Method.*Hits/ { getline; while ($0 ~ /\|/) { 
            gsub(/^[ \t]+|[ \t]+$/, "", $2); 
            gsub(/^[ \t]+|[ \t]+$/, "", $3); 
            gsub(/^[ \t]+|[ \t]+$/, "", $4); 
            if ($4 ~ /^[0-9]+$/) { 
                printf("├─ <b>%s</b>\n│  ├─ روش: %s\n│  └─ تعداد: %s\n", $2, $3, $4) 
            }; getline 
        }}
    ' | sed '$s/├─/└─/')

    # متریکس: پارسرها
    local parser_metrics=$(sudo cscli metrics 2>/dev/null | awk -F'│' '
        /Parsers/ { getline; while ($0 ~ /\|/) { 
            gsub(/^[ \t]+|[ \t]+$/, "", $2); 
            gsub(/^[ \t]+|[ \t]+$/, "", $3); 
            gsub(/^[ \t]+|[ \t]+$/, "", $4); 
            if ($3 ~ /^[0-9-]+$/) { 
                printf("├─ <b>%s</b>\n│  ├─ بازدید: %s\n│  ├─ پردازش‌شده: %s\n│  └─ پردازش‌نشده: %s\n", $2, $3, $4, $5) 
            }; getline 
        }}
    ' | sed '$s/├─/└─/')

    # ساخت گزارش
    local report=""
    report+="<b>🛡️ گزارش امنیتی CrowdSec</b>\n"
    report+="<pre>$(date +"%Y-%m-%d %H:%M:%S")</pre>\n"
    report+="────────────────────\n"
    report+="<b>⏳ دوره</b>: 24 ساعت اخیر\n"
    report+="<b>📧 ایمیل</b>: <code>${CONSOLE_EMAIL}</code>\n"
    report+="────────────────────\n"
    report+="<b>🔴 حملات شناسایی‌شده</b>\n${attacks_report}\n"
    report+="────────────────────\n"
    report+="<b>🔵 IPهای مسدود‌شده</b>\n${bans_report}\n"
    report+="────────────────────\n"
    report+="<b>📈 متریکس لاگ‌ها</b>\n${log_metrics:-└─ اطلاعاتی در دسترس نیست}\n"
    report+="────────────────────\n"
    report+="<b>🚫 دلایل مسدودسازی</b>\n${ban_reasons:-└─ اطلاعاتی در دسترس نیست}\n"
    report+="────────────────────\n"
    report+="<b>🌐 درخواست‌های API</b>\n${api_metrics:-└─ اطلاعاتی در دسترس نیست}\n"
    report+="────────────────────\n"
    report+="<b>🔍 متریکس پارسرها</b>\n${parser_metrics:-└─ اطلاعاتی در دسترس نیست}\n"
    report+="────────────────────\n"

    send_telegram "$report"
}

main() {
    echo "Starting security report generation..."
    generate_security_report
    echo "Report generation completed. Check $LOG_FILE or Telegram for results."
}

main
