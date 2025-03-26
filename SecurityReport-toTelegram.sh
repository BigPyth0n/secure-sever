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

# تابع ارسال به تلگرام با فرمت‌دهی پیشرفته
send_telegram() {
    local message="$1"
    local escaped_message=$(echo "$message" | sed 's/_/\\_/g' | sed 's/*/\\*/g' | sed 's/`/\\`/g')
    
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TELEGRAM_CHAT_ID" \
        -d "text=$escaped_message" \
        -d "parse_mode=MarkdownV2" >> "$LOG_FILE" 2>&1
}

# تابع تولید گزارش امنیتی
generate_security_report() {
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
            last_attack: (max_by(.time).time,
            sample_ips: [.[].ip] | unique | join(", "),
            countries: [.[].country] | unique | join(", ")
        }) |
        sort_by(.count) | reverse
    ')

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
            first_seen: (min_by(.duration).duration
        })
    ')

    # ساخت گزارش
    local report="
*🛡️ گزارش امنیتی CrowdSec*  
*⏳ دوره زمانی: 24 ساعت اخیر*  
*📧 ایمیل: \`$CONSOLE_EMAIL\`*  
*══════════════════════════*  

*🔴 حملات شناسایی شده*  
$(echo "$attacks_report" | jq -r '.[] | 
"▫️ *\(.type)*  
   - تعداد: \(.count)  
   - آخرین حمله: \(.last_attack)  
   - کشورها: \(.countries)  
   - نمونه IPها: \(.sample_ips)\n"')

*🔵 آی‌پی‌های در حال مسدود*  
$(echo "$banned_ips" | jq -r '.[] | 
"▪️ \(.ip)  
   - علت: \(.reason)  
   - کشور: \(.country)  
   - مدت بلاک: \(.first_seen)\n"')

*📊 آمار کلی*  
\`\`\`
$(sudo cscli metrics 2>/dev/null)
\`\`\`
"

    # ارسال گزارش
    send_telegram "$report"
    
    # ذخیره در فایل لاگ
    echo "[$(date)] Report sent to Telegram" >> "$LOG_FILE"
}

# =============================================
# اجرای اصلی
# =============================================
main() {
    echo "Starting security report generation..."
    generate_security_report
    echo "Report generation completed. Check Telegram for results."
}

# اجرای تابع اصلی
main
