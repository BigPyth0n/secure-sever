#!/bin/bash

# تنظیمات تلگرام
TELEGRAM_BOT_TOKEN="5054947489:AAFSNuI5JP0MhywlkZQIlePqubUpfVFhH9Q"
TELEGRAM_CHAT_ID="59941862"
CONSOLE_EMAIL="kitzone.ir@gmail.com"

# تابع ارسال به تلگرام
send_telegram() {
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TELEGRAM_CHAT_ID" \
        -d "text=$1" \
        -d "parse_mode=MarkdownV2"
}

# تولید گزارش حملات
generate_report() {
    # دریافت آخرین حملات (24 ساعت گذشته)
    local attacks=$(sudo cscli alerts list --since 24h -o json | jq -r '
        group_by(.scenario) |
        map({
            type: .[0].scenario,
            count: length,
            last_attack: (.[0].created_at | fromdate | strftime("%Y-%m-%d %H:%M")),
            ips: [.[].source_ip] | unique | join(", ")
        }) | sort_by(.count) | reverse
    ')

    # ساخت پیام
    local message="*🛡️ CrowdSec Security Report* \\- $(date +'%Y-%m-%d %H:%M')  
    *Email:* \`$CONSOLE_EMAIL\`  
    *═════════════════════*  
    "

    # اضافه کردن اطلاعات حملات
    message+="*🔴 Last 24h Attacks:*\n"
    message+=$(echo "$attacks" | jq -r '.[] | 
        "▫️ *\(.type)*  
        \\- Count: \(.count)  
        \\- Last: \(.last_attack)  
        \\- IPs: \(.ips)\n"
    ')

    # آمار کلی
    message+="*📊 Statistics:*\n"
    message+=$(sudo cscli metrics | awk '{print "• " $0}' | sed 's/://g')

    send_telegram "$message"
}

# اجرای گزارش
generate_report
