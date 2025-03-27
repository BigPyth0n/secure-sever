#!/bin/bash

# تنظیمات اصلی
TELEGRAM_BOT_TOKEN="5054947489:AAFSNuI5JP0MhywlkZQIlePqubUpfVFhH9Q"
TELEGRAM_CHAT_ID="59941862"
CONSOLE_EMAIL="kitzone.ir@gmail.com"
LOG_FILE="/var/log/crowdsec_reports.log"

# تابع ارسال به تلگرام
send_telegram() {
    local message="$1"
    # تبدیل کاراکترهای خاص برای Markdown
    message=$(echo "$message" | sed 's/\*/★/g; s/_/＿/g; s/`/ˋ/g; s/|/∣/g; s/-/－/g')
    
    # ارسال به تلگرام
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TELEGRAM_CHAT_ID" \
        -d "text=$message" \
        -d "parse_mode=Markdown" >> "$LOG_FILE" 2>&1
    
    if [ $? -eq 0 ]; then
        echo "[$(date +"%Y-%m-%d %H:%M:%S")] ✅ گزارش به تلگرام ارسال شد" | tee -a "$LOG_FILE"
    else
        echo "[$(date +"%Y-%m-%d %H:%M:%S")] ❌ خطا در ارسال به تلگرام" | tee -a "$LOG_FILE"
    fi
}

# تابع پردازش جدول‌های cscli
parse_table() {
    local input="$1"
    local headers="$2"
    echo "$input" | awk -v headers="$headers" '
    BEGIN { 
        FS = "\\|";
        split(headers, h, "|");
    }
    NR > 2 && !/^\+/ && !/^$/ && !/^---/ {
        gsub(/^[ \t]+|[ \t]+$/, "");
        for (i=1; i<=NF; i++) {
            gsub(/^[ \t]+|[ \t]+$/, "", $i);
            if ($i != "") {
                printf "• %s\n", $1;
                for (j=2; j<=NF; j++) {
                    if ($j != "" && h[j] != "") {
                        printf "  - %s: %s\n", h[j], $j;
                    }
                }
                printf "\n";
                break;
            }
        }
    }'
}

# تابع اصلی تولید گزارش
generate_security_report() {
    # حملات 24 ساعت اخیر
    local attacks=$(sudo cscli alerts list --since 24h 2>/dev/null)
    local attacks_report
    if [ -z "$attacks" ] || echo "$attacks" | grep -q "No active alerts"; then
        attacks_report="• هیچ حمله‌ای یافت نشد\n"
    else
        attacks_report=$(parse_table "$attacks" "|سناریو|IP|زمان|کشور")
    fi

    # IPهای مسدود شده
    local bans=$(sudo cscli decisions list 2>/dev/null)
    local bans_report
    if [ -z "$bans" ] || echo "$bans" | grep -q "No active decisions"; then
        bans_report="• هیچ IP مسدودی یافت نشد\n"
    else
        bans_report=$(parse_table "$bans" "|IP|علت|مدت|کشور")
    fi

    # متریکس سیستم
    local metrics=$(sudo cscli metrics 2>/dev/null)
    
    # پردازش دلایل مسدودسازی
    local ban_reasons=$(echo "$metrics" | awk '
        /Reason.*Origin/ {
            flag=1; getline; getline;
            while ($0 !~ /^\+/ && $0 !~ /^$/ && $0 !~ /^---/) {
                if ($0 ~ /\|/) {
                    gsub(/^[ \t]+|[ \t]+$/, "");
                    split($0, parts, "|");
                    if (parts[1] != "" && parts[4] ~ /[0-9]/) {
                        printf "• %s\n  - منبع: %s\n  - اقدام: %s\n  - تعداد: %s\n\n", 
                            parts[1], parts[2], parts[3], parts[4];
                    }
                }
                getline;
            }
        }')

    # پردازش درخواست‌های API
    local api_metrics=$(echo "$metrics" | awk '
        /Route.*Method/ {
            flag=1; getline; getline;
            while ($0 !~ /^\+/ && $0 !~ /^$/ && $0 !~ /^---/) {
                if ($0 ~ /\|/) {
                    gsub(/^[ \t]+|[ \t]+$/, "");
                    split($0, parts, "|");
                    if (parts[1] != "" && parts[3] ~ /[0-9]/) {
                        printf "• %s\n  - روش: %s\n  - تعداد: %s\n\n", 
                            parts[1], parts[2], parts[3];
                    }
                }
                getline;
            }
        }')

    # پردازش وضعیت لاگ‌ها
    local log_metrics=$(echo "$metrics" | awk '
        /Source.*Lines read/ {
            flag=1; getline;
            while ($0 !~ /^\+/ && $0 !~ /^$/ && $0 !~ /^---/) {
                if ($0 ~ /file:\/var\/log/ && $0 ~ /\|/) {
                    gsub(/^[ \t]+|[ \t]+$/, "");
                    split($0, parts, "|");
                    if (parts[1] != "" && parts[2] ~ /[0-9]/) {
                        printf "• %s\n  - خوانده‌شده: %s\n  - پردازش‌شده: %s\n  - پردازش‌نشده: %s\n\n", 
                            parts[1], parts[2], parts[3], parts[4];
                    }
                }
                getline;
            }
        }')

    # سناریوهای فعال
    local scenarios=$(sudo cscli scenarios list 2>/dev/null)
    local scenarios_report
    if [ -z "$scenarios" ] || echo "$scenarios" | grep -q "No scenarios installed"; then
        scenarios_report="• هیچ سناریوی فعالی یافت نشد\n"
    else
        scenarios_report=$(echo "$scenarios" | awk '
        BEGIN { count = 0; }
        NR > 2 && !/^\+/ && !/^$/ && !/^---/ && !/Name/ && count < 10 {
            gsub(/^[ \t]+|[ \t]+$/, "");
            if ($0 ~ /\|/) {
                split($0, parts, "|");
                gsub(/^[ \t]+|[ \t]+$/, "", parts[1]);
                gsub(/^[ \t]+|[ \t]+$/, "", parts[2]);
                if (parts[1] != "" && parts[1] !~ /^-+$/) {
                    printf "• %s\n  - وضعیت: %s\n\n", parts[1], parts[2];
                    count++;
                }
            }
        }')
    fi

    # ساخت گزارش نهایی
    local report="🛡️ گزارش امنیتی CrowdSec\n"
    report+="⏰ زمان: $(date +"%Y-%m-%d %H:%M:%S")\n"
    report+="⏳ دوره: 24 ساعت اخیر\n"
    report+="📧 ایمیل: ${CONSOLE_EMAIL}\n"
    report+="────────────────────\n"
    report+="🔴 حملات شناسایی‌شده\n${attacks_report}\n"
    report+="────────────────────\n"
    report+="🔵 IPهای مسدود‌شده\n${bans_report}\n"
    report+="────────────────────\n"
    report+="🚫 دلایل مسدودسازی\n${ban_reasons:-• اطلاعاتی در دسترس نیست}\n"
    report+="────────────────────\n"
    report+="🌐 درخواست‌های API\n${api_metrics:-• اطلاعاتی در دسترس نیست}\n"
    report+="────────────────────\n"
    report+="📈 وضعیت مانیتورینگ لاگ‌ها\n${log_metrics:-• اطلاعاتی در دسترس نیست}\n"
    report+="────────────────────\n"
    report+="🔧 سناریوهای فعال (10 مورد اول)\n${scenarios_report:-• اطلاعاتی در دسترس نیست}\n"
    report+="────────────────────\n"

    echo "$report"
}

# اجرای اصلی
echo "Starting security report generation..." | tee -a "$LOG_FILE"
report=$(generate_security_report)
echo "$report" >> "$LOG_FILE"
send_telegram "$report"
echo "Report generation completed." | tee -a "$LOG_FILE"
