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

# تابع ارسال به تلگرام با فرمت HTML
send_telegram() {
    local message="$1"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    # بررسی پیش‌نیاز curl
    if ! command -v curl &>/dev/null; then
        echo "[$timestamp] ❌ خطا: curl نصب نیست" | tee -a "$LOG_FILE"
        return 1
    fi

    # ارسال پیام
    local response=$(curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TELEGRAM_CHAT_ID" \
        -d "text=$message" \
        -d "parse_mode=HTML" 2>&1)

    # بررسی موفقیت ارسال
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
    # بررسی پیش‌نیازها
    if ! command -v cscli &>/dev/null || ! command -v jq &>/dev/null; then
        local error_msg="❌ خطا: cscli یا jq نصب نیست"
        send_telegram "$error_msg"
        echo "$(date) $error_msg" >> "$LOG_FILE"
        return 1
    fi

    # دریافت اطلاعات حملات 24 ساعت اخیر
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

    # دریافت IPهای مسدود شده فعلی
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
        })
    ' 2>/dev/null || echo "[]")

    # دریافت آمار کلی
    local metrics=$(sudo cscli metrics 2>/dev/null | sed 's/│/|/g' | grep -v '+-' || echo "اطلاعات در دسترس نیست")

    # ساخت گزارش با فرمت HTML
    local report=""
    report+="<b>🛡️ گزارش امنیتی CrowdSec</b>\n"
    report+="<pre>$(date +"%Y-%m-%d %H:%M:%S")</pre>\n"
    report+="────────────────────\n\n"
    report+="<b>⏳ دوره زمانی</b>: 24 ساعت اخیر\n"
    report+="<b>📧 ایمیل</b>: <code>${CONSOLE_EMAIL}</code>\n\n"

    # حملات شناسایی‌شده
    report+="<b>🔴 حملات شناسایی‌شده</b>\n"
    if [ "$attacks_report" != "[]" ]; then
        report+=$(echo "$attacks_report" | jq -r '.[] | 
            "├─ <b>\(.type)</b>\n" +
            "│  ├─ تعداد: \(.count)\n" +
            "│  ├─ آخرین حمله: \(.last_attack)\n" +
            "│  ├─ کشورها: \(.countries)\n" +
            "│  └─ نمونه IPها: <code>\(.sample_ips)</code>\n"')
        report="${report%├─*}└─${report##*├─}"  # تبدیل آخرین ├─ به └─
    else
        report+="└─ هیچ حمله‌ای یافت نشد\n"
    fi
    report+="\n"

    # IPهای مسدود شده
    report+="<b>🔵 IPهای در حال مسدود</b>\n"
    if [ "$banned_ips" != "[]" ]; then
        report+=$(echo "$banned_ips" | jq -r '.[] | 
            "├─ <b>\(.ip)</b>\n" +
            "│  ├─ علت: \(.reason)\n" +
            "│  ├─ کشور: \(.country)\n" +
            "│  └─ مدت بلاک: \(.first_seen)\n"')
        report="${report%├─*}└─${report##*├─}"  # تبدیل آخرین ├─ به └─
    else
        report+="└─ هیچ IP مسدودی یافت نشد\n"
    fi
    report+="\n"

    # آمار کلی
    report+="<b>📊 آمار کلی</b>\n"
    report+="<pre>${metrics}</pre>\n"

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
