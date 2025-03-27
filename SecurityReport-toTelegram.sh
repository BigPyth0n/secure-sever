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

    message=$(echo -e "$message")
    message=$(echo "$message" | sed 's/\*/\\*/g' | sed 's/_/\\_/g' | sed 's/`/\\`/g' | sed 's/|/\\|/g' | sed 's/-/\\-/g' | sed 's/\[/\\[/g' | sed 's/\]/\\]/g' | sed 's/(/\\(/g' | sed 's/)/\\)/g' | sed 's/#/\\#/g' | sed 's/+/\\+/g' | sed 's/!/\\!/g')

    local parts=()
    local max_length=4000
    while [ -n "$message" ]; do
        if [ ${#message} -le $max_length ]; then
            parts+=("$message")
            break
        else
            local part="${message:0:$max_length}"
            local last_newline=$(echo "$part" | grep -aob '\n' | tail -1 | cut -d: -f1)
            if [ -n "$last_newline" ] && [ "$last_newline" -gt 0 ]; then
                part="${message:0:$((last_newline + 1))}"
            else
                part="${message:0:$max_length}\n"
            fi
            parts+=("$part")
            message="${message:${#part}}"
        fi
    done

    local part_count=1
    for part in "${parts[@]}"; do
        echo "[$timestamp] ارسال بخش $part_count - طول: ${#part}" >> "$LOG_FILE"
        local response=$(curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
            -d "chat_id=$TELEGRAM_CHAT_ID" \
            -d "text=$part" \
            -d "parse_mode=Markdown" 2>&1)

        if echo "$response" | grep -q '"ok":true'; then
            echo "[$timestamp] ✅ بخش $part_count ارسال شد" | tee -a "$LOG_FILE"
        else
            echo "[$timestamp] ❌ خطا در ارسال بخش $part_count: $response" | tee -a "$LOG_FILE"
            return 1
        fi
        part_count=$((part_count + 1))
    done
    return 0
}

generate_security_report() {
    install_prerequisites || return 1

    # حملات 24 ساعت اخیر
    local attacks=$(sudo cscli alerts list --since 24h -o json 2>/dev/null || echo "خطا در دریافت حملات")
    if [ "$(echo "$attacks" | jq -r 'length')" -eq 0 ]; then
        local attacks_report="• هیچ حمله‌ای یافت نشد\n"
    else
        local attacks_report=$(echo "$attacks" | jq -r '.[] | "• **سناریو: \(.scenario)**\n  - IP: \(.source.ip)\n  - زمان: \(.created_at)\n  - کشور: \(.source.scope)\n"')
    fi

    # IPهای مسدود شده
    local bans=$(sudo cscli decisions list -o json 2>/dev/null || echo "خطا در دریافت IPهای مسدود")
    if [ "$(echo "$bans" | jq -r 'length')" -eq 0 ]; then
        local bans_report="• هیچ IP مسدودی یافت نشد\n"
    else
        local bans_report=$(echo "$bans" | jq -r '.[] | "• **IP: \(.value)**\n  - علت: \(.scenario)\n  - مدت: \(.duration)\n  - کشور: \(.origin)\n"')
    fi

    # متریکس سیستم
    local metrics=$(sudo cscli metrics 2>/dev/null || echo "خطا در دریافت متریکس")
    echo "Metrics Raw:\n$metrics" >> "$LOG_FILE"

    # پردازش متریکس لاگ‌ها
    local log_metrics=$(echo "$metrics" | awk '
        /^\+.*\+$/ {next}
        /file:\/var\/log/ {
            gsub(/^[ \t]+|[ \t]+$/, "");
            split($0, parts, "|");
            gsub(/^[ \t]+|[ \t]+$/, "", parts[1]);
            gsub(/^[ \t]+|[ \t]+$/, "", parts[2]);
            gsub(/^[ \t]+|[ \t]+$/, "", parts[3]);
            gsub(/^[ \t]+|[ \t]+$/, "", parts[4]);
            printf("• **%s**\n  - خوانده‌شده: %s\n  - پردازش‌شده: %s\n  - پردازش‌نشده: %s\n", parts[1], parts[2], parts[3], parts[4]);
        }
    ')

    # پردازش دلایل مسدودسازی
    local ban_reasons=$(echo "$metrics" | awk '
        /^\+.*\+$/ {next}
        /Reason.*Count/ {flag=1; next}
        flag && /^[^+]/ {
            gsub(/^[ \t]+|[ \t]+$/, "");
            split($0, parts, "|");
            gsub(/^[ \t]+|[ \t]+$/, "", parts[1]);
            gsub(/^[ \t]+|[ \t]+$/, "", parts[2]);
            gsub(/^[ \t]+|[ \t]+$/, "", parts[3]);
            gsub(/^[ \t]+|[ \t]+$/, "", parts[4]);
            if (parts[4] ~ /^[0-9]+$/) {
                printf("• **%s**\n  - منبع: %s\n  - اقدام: %s\n  - تعداد: %s\n", parts[1], parts[2], parts[3], parts[4]);
            }
        }
    ')

    # پردازش درخواست‌های API
    local api_metrics=$(echo "$metrics" | awk '
        /^\+.*\+$/ {next}
        /Route.*Hits/ {flag=1; next}
        flag && /^[^+]/ {
            gsub(/^[ \t]+|[ \t]+$/, "");
            split($0, parts, "|");
            gsub(/^[ \t]+|[ \t]+$/, "", parts[1]);
            gsub(/^[ \t]+|[ \t]+$/, "", parts[2]);
            gsub(/^[ \t]+|[ \t]+$/, "", parts[3]);
            if (parts[3] ~ /^[0-9]+$/) {
                printf("• **%s**\n  - روش: %s\n  - تعداد: %s\n", parts[1], parts[2], parts[3]);
            }
        }
    ')

    # سناریوهای فعال (نسخه اصلاح شده)
    local scenarios=$(sudo cscli scenarios list -o json 2>/dev/null || echo "خطا در دریافت سناریوها")
    if [ "$(echo "$scenarios" | jq -r 'length')" -eq 0 ]; then
        local scenarios_report="• هیچ سناریوی فعالی یافت نشد\n"
    else
        local scenarios_report=$(echo "$scenarios" | jq -r '
            if type == "array" then
                .[] | 
                if .status? == "enabled" then
                    "• **\(.name)**\n  - وضعیت: فعال\n"
                elif .activated? == true then
                    "• **\(.name)**\n  - وضعیت: فعال\n"
                else
                    empty
                end
            else
                empty
            end' | head -n 10)
        
        if [ -z "$scenarios_report" ]; then
            scenarios_report="• اطلاعات وضعیت سناریوها در دسترس نیست\n"
        fi
    fi

    # ساخت گزارش
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
    report+="**🚫 دلایل مسدودسازی**  \n"
    report+="${ban_reasons:-• اطلاعاتی در دسترس نیست}\n"
    report+="────────────────────  \n"
    report+="**🌐 درخواست‌های API**  \n"
    report+="${api_metrics:-• اطلاعاتی در دسترس نیست}\n"
    report+="────────────────────  \n"
    report+="**📈 وضعیت مانیتورینگ لاگ‌ها**  \n"
    report+="${log_metrics:-• اطلاعاتی در دسترس نیست}\n"
    report+="────────────────────  \n"
    report+="**🔧 سناریوهای فعال (10 مورد اول)**  \n"
    report+="${scenarios_report}\n"
    report+="────────────────────  \n"

    send_telegram "$report"
}

main() {
    echo "Starting security report generation..." | tee -a "$LOG_FILE"
    generate_security_report
    echo "Report generation completed. Check $LOG_FILE or Telegram for results." | tee -a "$LOG_FILE"
}

main
