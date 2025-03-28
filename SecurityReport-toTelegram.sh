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
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    # تبدیل \n به خط جدید واقعی
    message=$(echo -e "$message")

    # اسکیپ کردن همه کاراکترهای خاص برای Markdown
    message=$(echo "$message" | sed 's/\*/\\*/g; s/_/\\_/g; s/`/\\`/g; s/|/\\|/g; s/-/\\-/g; s/\[/\\[/g; s/\]/\\]/g; s/(/\\(/g; s/)/\\)/g; s/#/\\#/g; s/+/\\+/g; s/!/\\!/g')

    # ذخیره پیام برای دیباگ
    echo "[$timestamp] پیام قبل از تقسیم:\n$message" >> "$LOG_FILE"
    echo "[$timestamp] طول پیام: ${#message}" >> "$LOG_FILE"

    # تقسیم پیام به بخش‌های 4000 کاراکتری (کمی کمتر از 4096 برای احتیاط)
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

    # ارسال هر بخش
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
        sleep 1
    done
}




generate_security_report() {
    install_prerequisites

    # حملات 24 ساعت اخیر
    local attacks=$(sudo cscli alerts list --since 24h 2>/dev/null || echo "خطا در دریافت حملات")
    if echo "$attacks" | grep -q "No active alerts"; then
        local attacks_report="• هیچ حمله‌ای یافت نشد\n"
    else
        local attacks_report=$(echo "$attacks" | awk '
            NR>2 && !/^\+/ {
                printf("• **سناریو: %s**\n  - IP: %s\n  - زمان: %s\n", $1, $2, $3)
            }')
    fi

    # IPهای مسدود شده (با اطلاعات جغرافیایی)
    local bans=$(sudo cscli decisions list 2>/dev/null || echo "خطا در دریافت IPهای مسدود")
    if echo "$bans" | grep -q "No active decisions"; then
        local bans_report="• هیچ IP مسدودی یافت نشد\n"
    else
        local bans_report=$(sudo cscli decisions list --no-color -o json 2>/dev/null | jq -r '
            .[] | 
            "• **IP: " + .value + "**\n  - علت: " + .reason + "\n  - مدت: " + .duration + "\n  - کشور: " + (.country // "نامشخص")' 2>/dev/null)
    fi

    # متریکس خام برای دیباگ
    local metrics=$(sudo cscli metrics --no-color 2>/dev/null || echo "خطا در دریافت متریکس")
    echo "Metrics Raw:\n$metrics" >> "$LOG_FILE"
    metrics=$(echo "$metrics" | sed 's/│/|/g')

    # متریکس: لاگ‌ها (اصلاح‌شده برای انعطاف‌پذیری بیشتر)
    local log_metrics=$(echo "$metrics" | awk '
        BEGIN { found=0 }
        /Acquisition Metrics/ { found=1; getline; getline; next }
        found && /file:/ { 
            split($0, parts, "|");
            gsub(/^[ \t]+|[ \t]+$/, "", parts[1]);
            gsub(/^[ \t]+|[ \t]+$/, "", parts[2]);
            gsub(/^[ \t]+|[ \t]+$/, "", parts[3]);
            gsub(/^[ \t]+|[ \t]+$/, "", parts[4]);
            if (parts[2] ~ /^[0-9-]+$/) {
                printf("• **%s**\n  - خوانده‌شده: %s\n  - پردازش‌شده: %s\n  - پردازش‌نشده: %s\n", parts[1], parts[2], parts[3], parts[4])
            }
        }
        /Local API Decisions/ { found=0 }
    ')
    echo "Log Metrics Extracted:\n$log_metrics" >> "$LOG_FILE"

    # متریکس: دلایل مسدودسازی
    local ban_reasons=$(echo "$metrics" | awk '
        BEGIN { found=0 }
        /Local API Decisions/ { found=1; getline; getline; next }
        found && /\|/ { 
            split($0, parts, "|");
            gsub(/^[ \t]+|[ \t]+$/, "", parts[2]);
            gsub(/^[ \t]+|[ \t]+$/, "", parts[3]);
            gsub(/^[ \t]+|[ \t]+$/, "", parts[4]);
            gsub(/^[ \t]+|[ \t]+$/, "", parts[5]);
            if (parts[5] ~ /^[0-9]+$/) {
                printf("• **%s**\n  - منبع: %s\n  - اقدام: %s\n  - تعداد: %s\n", parts[2], parts[3], parts[4], parts[5])
            }
        }
        /Local API Metrics/ { found=0 }
    ')
    echo "Ban Reasons Extracted:\n$ban_reasons" >> "$LOG_FILE"

    # متریکس: درخواست‌های API
    local api_metrics=$(echo "$metrics" | awk '
        BEGIN { found=0 }
        /Local API Metrics/ { found=1; getline; getline; next }
        found && /\|/ { 
            split($0, parts, "|");
            gsub(/^[ \t]+|[ \t]+$/, "", parts[2]);
            gsub(/^[ \t]+|[ \t]+$/, "", parts[3]);
            gsub(/^[ \t]+|[ \t]+$/, "", parts[4]);
            if (parts[4] ~ /^[0-9]+$/) {
                printf("• **%s**\n  - روش: %s\n  - تعداد: %s\n", parts[2], parts[3], parts[4])
            }
        }
        /Local API Machines Metrics/ { found=0 }
    ')
    echo "API Metrics Extracted:\n$api_metrics" >> "$LOG_FILE"

    # سناریوهای فعال (اصلاح‌شده برای انعطاف‌پذیری بیشتر)
    local scenarios=$(echo "$metrics" | awk '
        BEGIN { found=0; count=0 }
        /Scenario Metrics/ { found=1; getline; getline; next }
        found && /crowdsecurity\// { 
            split($0, parts, "|");
            gsub(/^[ \t]+|[ \t]+$/, "", parts[1]);
            gsub(/^[ \t]+|[ \t]+$/, "", parts[2]);
            if (parts[2] ~ /^[0-9-]+$/) {
                printf("• **%s**\n  - موارد فعال: %s\n", parts[1], parts[2]);
                count++;
                if (count >= 10) exit;
            }
        }
        /Whitelist Metrics/ { found=0 }
    ')
    echo "Scenarios Extracted:\n$scenarios" >> "$LOG_FILE"

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
    report+="${bans_report:-• اطلاعاتی در دسترس نیست}\n"
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
    report+="${scenarios:-• اطلاعاتی در دسترس نیست}\n"
    report+="────────────────────  \n"

    send_telegram "$report"
}





# اجرای اصلی
echo "Starting security report generation..."
generate_security_report
echo "Report generation completed."
