#!/bin/bash

# تنظیمات اصلی
TELEGRAM_BOT_TOKEN="5054947489:AAFSNuI5JP0MhywlkZQIlePqubUpfVFhH9Q"
TELEGRAM_CHAT_ID="59941862"
CONSOLE_EMAIL="kitzone.ir@gmail.com"
LOG_FILE="/var/log/crowdsec_reports.log"

# توابع
install_prerequisites() {
    local missing_tools=()
    command -v curl &>/dev/null || missing_tools+=("curl")
    command -v jq &>/dev/null || missing_tools+=("jq")
    command -v cscli &>/dev/null || missing_tools+=("crowdsec")

    if [ ${#missing_tools[@]} -gt 0 ]; then
        apt update -y && apt install -y "${missing_tools[@]}"
    fi
}

send_telegram() {
    local message="$1"
    message=$(echo -e "$message" | sed 's/\*/\\*/g; s/_/\\_/g; s/`/\\`/g; s/|/\\|/g')
    
    # تقسیم پیام به بخش‌های کوچک‌تر
    while [ -n "$message" ]; do
        local part=$(echo "$message" | head -c 4000)
        local response=$(curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
            -d "chat_id=$TELEGRAM_CHAT_ID" \
            -d "text=$part" \
            -d "parse_mode=Markdown")
        
        message="${message:4000}"
        sleep 1
    done
}

generate_security_report() {
    install_prerequisites

    # حملات 24 ساعت اخیر
    local attacks_report
    if sudo cscli alerts list --since 24h | grep -q "No active alerts"; then
        attacks_report="• هیچ حمله‌ای یافت نشد\n"
    else
        attacks_report=$(sudo cscli alerts list --since 24h | awk '
            NR>2 && !/^\+/ {
                printf("• **سناریو: %s**\n  - IP: %s\n  - زمان: %s\n", $1, $2, $3)
            }')
    fi

    # IPهای مسدود شده
    local bans_report
    if sudo cscli decisions list | grep -q "No active decisions"; then
        bans_report="• هیچ IP مسدودی یافت نشد\n"
    else
        bans_report=$(sudo cscli decisions list | awk '
            NR>2 && !/^\+/ {
                printf("• **IP: %s**\n  - علت: %s\n  - مدت: %s\n", $1, $2, $3)
            }')
    fi

    # متریکس سیستم
    local metrics=$(sudo cscli metrics 2>/dev/null)

    # پردازش متریکس
    local ban_reasons=$(echo "$metrics" | awk '
        /Reason/ {
            flag=1; getline; getline
            while ($0 !~ /^\+/ && $0 !~ /^$/) {
                gsub(/^[ \t]+|[ \t]+$/, "");
                split($0, parts, "|");
                printf("• **%s**\n  - منبع: %s\n  - اقدام: %s\n  - تعداد: %s\n", 
                    parts[1], parts[2], parts[3], parts[4])
                getline
            }
        }')

    local api_metrics=$(echo "$metrics" | awk '
        /Route/ {
            flag=1; getline; getline
            while ($0 !~ /^\+/ && $0 !~ /^$/) {
                gsub(/^[ \t]+|[ \t]+$/, "");
                split($0, parts, "|");
                printf("• **%s**\n  - روش: %s\n  - تعداد: %s\n", 
                    parts[1], parts[2], parts[3])
                getline
            }
        }')

    local log_metrics=$(echo "$metrics" | awk '
        /file:\/var\/log/ {
            gsub(/^[ \t]+|[ \t]+$/, "");
            split($0, parts, "|");
            printf("• **%s**\n  - خوانده‌شده: %s\n  - پردازش‌شده: %s\n  - پردازش‌نشده: %s\n", 
                parts[1], parts[2], parts[3], parts[4])
        }')

    # سناریوهای فعال (با روش مطمئن‌تر)
    local scenarios_report
    if sudo cscli scenarios list | grep -q "No scenarios installed"; then
        scenarios_report="• هیچ سناریوی فعالی یافت نشد\n"
    else
        scenarios_report=$(sudo cscli scenarios list | awk '
            NR>2 && !/^\+/ && !/Name/ {
                printf("• **%s**\n  - وضعیت: %s\n", $1, $2)
            }' | head -n 10)
    fi

    # ساخت گزارش
    local report="**🛡️ گزارش امنیتی CrowdSec**  \n"
    report+="**⏰ زمان**: $(date +"%Y-%m-%d %H:%M:%S")  \n"
    report+="**⏳ دوره**: 24 ساعت اخیر  \n"
    report+="**📧 ایمیل**: \`${CONSOLE_EMAIL}\`  \n"
    report+="────────────────────  \n"
    report+="**🔴 حملات شناسایی‌شده**  \n${attacks_report}\n"
    report+="────────────────────  \n"
    report+="**🔵 IPهای مسدود‌شده**  \n${bans_report}\n"
    report+="────────────────────  \n"
    report+="**🚫 دلایل مسدودسازی**  \n${ban_reasons:-• اطلاعاتی در دسترس نیست}\n"
    report+="────────────────────  \n"
    report+="**🌐 درخواست‌های API**  \n${api_metrics:-• اطلاعاتی در دسترس نیست}\n"
    report+="────────────────────  \n"
    report+="**📈 وضعیت مانیتورینگ لاگ‌ها**  \n${log_metrics:-• اطلاعاتی در دسترس نیست}\n"
    report+="────────────────────  \n"
    report+="**🔧 سناریوهای فعال (10 مورد اول)**  \n${scenarios_report:-• اطلاعاتی در دسترس نیست}\n"
    report+="────────────────────  \n"

    send_telegram "$report"
}

# اجرای اصلی
echo "Starting security report generation..."
generate_security_report
echo "Report generation completed."
