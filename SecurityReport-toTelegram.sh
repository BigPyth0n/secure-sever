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

# تابع نصب پیش‌نیازها
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
            echo "[$timestamp] ✅ پیش‌نیازها با موفقیت نصب شدند" | tee -a "$LOG_FILE"
        else
            echo "[$timestamp] ❌ خطا در نصب پیش‌نیازها" | tee -a "$LOG_FILE"
            return 1
        fi
    else
        echo "[$timestamp] ✅ همه پیش‌نیازها از قبل نصب هستند" | tee -a "$LOG_FILE"
    fi
    return 0
}

# تابع ارسال به تلگرام
send_telegram() {
    local message="$1"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    local response=$(curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TELEGRAM_CHAT_ID" \
        -d "text=$message" \
        -d "parse_mode=HTML" 2>&1)

    if echo "$response" | grep -q '"ok":true'; then
        echo "[$timestamp] ✅ گزارش با موفقیت به تلگرام ارسال شد" | tee -a "$LOG_FILE"
        return 0
    else
        echo "[$timestamp] ❌ خطا در ارسال به تلگرام: $response" | tee -a "$LOG_FILE"
        return 1
    fi
}

# تابع تولید گزارش امنیتی
generate_security_report() {
    install_prerequisites || return 1

    # حملات 24 ساعت اخیر
    local attacks_report=$(sudo cscli alerts list --since 24h -o json 2>/dev/null | jq -r '
        [.alerts[] | {
            type: .scenario,
            ip: .source_ip,
            time: (.created_at | fromdate | strftime("%Y-%m-%d %H:%M")),
            country: (.source.geo.country // "Unknown")
        }] | 
        group_by(.type) |
        map({
            type: .[0].type,
            count: length,
            last_attack: (max_by(.time) | .time),
            sample_ips: [.[].ip] | unique | join(", "),
            countries: [.[].country] | unique | join(", ")
        }) |
        sort_by(.count) | reverse
    ' 2>/dev/null || echo "[]")

    # IPهای مسدود شده
    local banned_ips=$(sudo cscli decisions list -o json 2>/dev/null | jq -r '
        [.decisions[] | {
            ip: .value,
            reason: .scenario,
            duration: .duration,
            country: (.origin // "Unknown")
        }] |
        group_by(.ip) |
        map({
            ip: .[0].ip,
            reason: .[0].reason,
            country: .[0].country,
            first_seen: (min_by(.duration) | .duration)
        }) |
        sort_by(.ip)
    ' 2>/dev/null || echo "[]")

    # متریکس ساده‌شده
    local metrics_summary=""
    # لاگ‌های خوانده‌شده
    local log_lines=$(sudo cscli metrics 2>/dev/null | awk -F'│' '
        /file:\/var\/log/ { 
            gsub(/^[ \t]+|[ \t]+$/, "", $1); 
            gsub(/^[ \t]+|[ \t]+$/, "", $2); 
            if ($2 ~ /^[0-9]+$/) { 
                printf("├─ <b>%s</b>: %s خط\n", $1, $2) 
            } 
        }
    ' | sed '$s/├─/└─/')
    # دلایل مسدودسازی
    local ban_reasons=$(sudo cscli metrics 2>/dev/null | awk -F'│' '
        /Reason/ { getline; while ($0 ~ /\|/) { 
            gsub(/^[ \t]+|[ \t]+$/, "", $2); 
            gsub(/^[ \t]+|[ \t]+$/, "", $5); 
            if ($5 ~ /^[0-9]+$/) { 
                printf("├─ <b>%s</b>: %s مورد\n", $2, $5) 
            }; getline 
        }}
    ' | sed '$s/├─/└─/')
    metrics_summary+="${log_lines}\n${ban_reasons}"

    # ساخت گزارش
    local report=""
    report+="<b>🛡️ گزارش امنیتی CrowdSec</b>\n"
    report+="<pre>$(date +"%Y-%m-%d %H:%M:%S")</pre>\n"
    report+="────────────────────\n"
    report+="<b>⏳ دوره</b>: 24 ساعت اخیر\n"
    report+="<b>📧 ایمیل</b>: <code>${CONSOLE_EMAIL}</code>\n"
    report+="────────────────────\n"

    # حملات
    report+="<b>🔴 حملات شناسایی‌شده</b>\n"
    if [ "$attacks_report" != "[]" ]; then
        report+=$(echo "$attacks_report" | jq -r '.[] | 
            "├─ <b>\(.type)</b>\n" +
            "│  ├─ تعداد: \(.count)\n" +
            "│  ├─ آخرین: \(.last_attack)\n" +
            "│  ├─ کشورها: \(.countries)\n" +
            "│  └─ IPها: <code>\(.sample_ips)</code>\n"')
        report="${report%├─*}└─${report##*├─}"
    else
        report+="└─ هیچ حمله‌ای یافت نشد\n"
    fi
    report+="────────────────────\n"

    # IPهای مسدود
    report+="<b>🔵 IPهای مسدود‌شده</b>\n"
    if [ "$banned_ips" != "[]" ]; then
        report+=$(echo "$banned_ips" | jq -r '.[] | 
            "├─ <b>\(.ip)</b>\n" +
            "│  ├─ علت: \(.reason)\n" +
            "│  ├─ کشور: \(.country)\n" +
            "│  └─ مدت: \(.first_seen)\n"')
        report="${report%├─*}└─${report##*├─}"
    else
        report+="└─ هیچ IP مسدودی یافت نشد\n"
    fi
    report+="────────────────────\n"

    # متریکس
    report+="<b>📊 آمار کلی</b>\n"
    if [ -n "$metrics_summary" ]; then
        report+="${metrics_summary}"
    else
        report+="└─ اطلاعاتی در دسترس نیست\n"
    fi
    report+="────────────────────\n"

    # ارسال گزارش
    send_telegram "$report"
}

# =============================================
# اجرای اصلی
# =============================================
main() {
    echo "Starting security report generation..."
    generate_security_report
    echo "Report generation completed. Check $LOG_FILE or Telegram for results."
}

# اجرای تابع اصلی
main
