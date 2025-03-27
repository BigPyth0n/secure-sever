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

    # اسکیپ کردن همه کاراکترهای خاص برای Markdown
    message=$(echo "$message" | sed 's/\\/\\\\/g' | sed 's/\*/\\*/g' | sed 's/_/\\_/g' | sed 's/`/\\`/g' | sed 's/|/\\|/g' | sed 's/-/\\-/g' | sed 's/\[/\\[/g' | sed 's/\]/\\]/g' | sed 's/(/\\(/g' | sed 's/)/\\)/g' | sed 's/#/\\#/g' | sed 's/+/\\+/g' | sed 's/!/\\!/g')

    # ذخیره پیام برای دیباگ
    echo "[$timestamp] پیام قبل از ارسال:\n$message" >> "$LOG_FILE"

    # تقسیم پیام به بخش‌های 4096 کاراکتری
    local parts=()
    while [ -n "$message" ]; do
        if [ ${#message} -le 4096 ]; then
            parts+=("$message")
            break
        else
            local part="${message:0:4096}"
            local last_newline=$(echo "$part" | grep -aob '\n' | tail -1 | cut -d: -f1)
            if [ -n "$last_newline" ]; then
                part="${message:0:$((last_newline + 1))}"
            fi
            parts+=("$part")
            message="${message:${#part}}"
        fi
    done

    # ارسال هر بخش
    for part in "${parts[@]}"; do
        local response=$(curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
            -d "chat_id=$TELEGRAM_CHAT_ID" \
            -d "text=$part" \
            -d "parse_mode=Markdown" 2>&1)

        if echo "$response" | grep -q '"ok":true'; then
            echo "[$timestamp] ✅ ارسال موفق" | tee -a "$LOG_FILE"
        else
            echo "[$timestamp] ❌ خطا: $response" | tee -a "$LOG_FILE"
            return 1
        fi
    done
    return 0
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

    # متریکس: لاگ‌ها
    local log_metrics=$(sudo cscli metrics 2>/dev/null | awk '
        BEGIN { FS="│"; found=0 }
        /Source.*Lines read.*Lines parsed.*Lines unparsed/ { found=1; getline; next }
        found && /file:\/var\/log/ { 
            gsub(/^[ \t]+|[ \t]+$/, "", $1); 
            gsub(/^[ \t]+|[ \t]+$/, "", $2); 
            gsub(/^[ \t]+|[ \t]+$/, "", $3); 
            gsub(/^[ \t]+|[ \t]+$/, "", $4); 
            if ($2 ~ /^[0-9-]+$/) { 
                printf("• **%s**\n  - خوانده‌شده: %s\n  - پردازش‌شده: %s\n  - پردازش‌نشده: %s\n", $1, $2, $3, $4) 
            } 
        }
        /Local API Decisions/ { found=0 }
    ')

    # متریکس: دلایل مسدودسازی
    local ban_reasons=$(sudo cscli metrics 2>/dev/null | awk '
        BEGIN { FS="│"; found=0 }
        /Reason.*Origin.*Action.*Count/ { found=1; getline; next }
        found && /\|/ { 
            gsub(/^[ \t]+|[ \t]+$/, "", $2); 
            gsub(/^[ \t]+|[ \t]+$/, "", $3); 
            gsub(/^[ \t]+|[ \t]+$/, "", $4); 
            gsub(/^[ \t]+|[ \t]+$/, "", $5); 
            if ($5 ~ /^[0-9]+$/) { 
                printf("• **%s**\n  - منبع: %s\n  - اقدام: %s\n  - تعداد: %s\n", $2, $3, $4, $5) 
            } 
        }
        /Local API Metrics/ { found=0 }
    ')

    # متریکس: درخواست‌های API
    local api_metrics=$(sudo cscli metrics 2>/dev/null | awk '
        BEGIN { FS="│"; found=0 }
        /Route.*Method.*Hits/ { found=1; getline; next }
        found && /\|/ { 
            gsub(/^[ \t]+|[ \t]+$/, "", $2); 
            gsub(/^[ \t]+|[ \t]+$/, "", $3); 
            gsub(/^[ \t]+|[ \t]+$/, "", $4); 
            if ($4 ~ /^[0-9]+$/) { 
                printf("• **%s**\n  - روش: %s\n  - تعداد: %s\n", $2, $3, $4) 
            } 
        }
        /Local API Machines Metrics/ { found=0 }
    ')

    # سناریوهای فعال
    local scenarios=$(sudo cscli scenarios list 2>/dev/null | awk '
        NR>2 { 
            printf("• **%s**\n  - وضعیت: %s\n", $1, $2) 
        }')

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
    report+="**🔧 سناریوهای فعال**  \n"
    report+="${scenarios:-• اطلاعاتی در دسترس نیست}\n"
    report+="────────────────────  \n"

    send_telegram "$report"
}

main() {
    echo "Starting security report generation..."
    generate_security_report
    echo "Report generation completed. Check $LOG_FILE or Telegram for results."
}

main
