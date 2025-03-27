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

    # تبدیل \n به خط جدید واقعی
    message=$(echo -e "$message")

    local response=$(curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TELEGRAM_CHAT_ID" \
        -d "text=$message" \
        -d "parse_mode=Markdown" 2>&1)

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
    local attacks=$(sudo cscli alerts list --since 24h 2>/dev/null || echo "خطا در دریافت حملات")
    if echo "$attacks" | grep -q "No active alerts"; then
        local attacks_report="• هیچ حمله‌ای یافت نشد\n"
    else
        local attacks_report=$(echo "$attacks" | awk '
            NR>2 { 
                printf("• **سناریو: %s**\n  - IP: %s\n  - زمان: %s\n  - کشور: %s\n", $1, $2, $3, $4) 
            }')
    fi

    # IPهای مسدود شده
    local bans=$(sudo cscli decisions list 2>/dev/null || echo "خطا در دریافت IPهای مسدود")
    if echo "$bans" | grep -q "No active decisions"; then
        local bans_report="• هیچ IP مسدودی یافت نشد\n"
    else
        local bans_report=$(echo "$bans" | awk '
            NR>2 { 
                printf("• **IP: %s**\n  - علت: %s\n  - مدت: %s\n  - کشور: %s\n", $1, $2, $3, $4) 
            }')
    fi

    # متریکس: خام
    local metrics=$(sudo cscli metrics 2>/dev/null || echo "خطا در دریافت متریکس")

    # ساخت گزارش با فرمت Markdown
    local report=""
    report+="**🛡️ گزارش امنیتی CrowdSec**  \n"
    report+="**⏰ زمان**: $(date +"%Y-%m-%d %H:%M:%S")  \n"
    report+="**⏳ دوره**: 24 ساعت اخیر  \n"
    report+="**📧 ایمیل**: \`${CONSOLE_EMAIL}\`  \n"
    report+="────────────────────  \n"
    report+="**🔴 حملات شناسایی‌شده**  \n"
    report+="${attacks_report}\n"
    report+="────────────────────  \n"
    report+="**🔵 IPهای مسدود‌شده**  \n"
    report+="${bans_report}\n"
    report+="────────────────────  \n"
    report+="**📊 متریکس**  \n"
    report+="\`\`\`  \n${metrics}\n\`\`\`  \n"
    report+="────────────────────  \n"

    send_telegram "$report"
}

main() {
    echo "Starting security report generation..."
    generate_security_report
    echo "Report generation completed. Check $LOG_FILE or Telegram for results."
}

main
