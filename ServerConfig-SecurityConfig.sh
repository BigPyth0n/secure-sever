#!/bin/bash
set -e

# =============================================
# تنظیمات اصلی (Config Variables)
# =============================================
TELEGRAM_BOT_TOKEN="5054947489:AAFSNuI5JP0MhywlkZQIlePqubUpfVFhH9Q"
TELEGRAM_CHAT_ID="59941862"
NEW_USER="bigpython"
SSH_PORT="9011"
CODE_SERVER_PORT="1010"
NETDATA_PORT="9001"
WAZUH_DASHBOARD_PORT="5601"
PORTAINER_PORT="9000"
NGINX_PROXY_MANAGER_PORT="81"
CODE_SERVER_PASSWORD="114aa2650b0db5509f36f4fc"
PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO8J++ag0NtV/AaQU9mF7X8qSKGrOy2Wu1eJISg72Zfs bigpython@TradePC"

# کاربر مخصوص SFTP
SFTP_USER="securftpuser"
SFTP_PASSWORD="uCkdYMqd5F@GGHYSKy9b"

# تنظیمات CrowdSec
CROWD_SEC_EMAIL="kitzone.ir@gmail.com"
CROWD_SEC_ENROLLMENT_TOKEN="cm8qh5k6b0007iacrx07s382h"

# پورت‌های باز و رزرو شده
PORTS_TO_OPEN=("80" "443" "$SSH_PORT" "$CODE_SERVER_PORT" "$NETDATA_PORT" "$WAZUH_DASHBOARD_PORT" "$PORTAINER_PORT" "$NGINX_PROXY_MANAGER_PORT")
RESERVED_PORTS=("1020" "1030" "1040" "2060" "3050" "2020" "4040" "3060" "2080")

# آرایه برای ذخیره وضعیت سرویس‌ها
declare -A SERVICE_STATUS

# =============================================
# توابع کمکی (Helper Functions)
# =============================================

# تابع اسکیپ کاراکترهای MarkdownV2
escape_markdown() {
    local text="$1"
    # اسکیپ کاراکترهای خاص برای MarkdownV2
    text=$(echo "$text" | sed 's/[][_*()~`>#+=|{}.!]/\\&/g')
    echo "$text"
}

# ارسال پیام به تلگرام با تلاش مجدد و مدیریت پیام‌های طولانی
send_telegram() {
    local message="$1"
    local max_retries=3
    local retry_count=0
    local success=0
    local error_msg=""
    local max_length=4096  # حداکثر طول پیام تلگرام
    
    # تقسیم پیام به بخش‌های 4096 کاراکتری
    while [ -n "$message" ]; do
        local part="${message:0:$max_length}"
        message="${message:$max_length}"
        
        # اسکیپ کاراکترهای خاص
        part=$(escape_markdown "$part")
        
        while [ $retry_count -lt $max_retries ]; do
            response=$(curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
                -d "chat_id=$TELEGRAM_CHAT_ID" \
                -d "text=$part" \
                -d "parse_mode=MarkdownV2" 2>&1)
            
            if echo "$response" | grep -q '"ok":true'; then
                success=1
                break
            else
                retry_count=$((retry_count + 1))
                error_msg=$(echo "$response" | grep -o '"description":"[^"]*"' | cut -d'"' -f4 || echo "$response")
                echo "⚠️ تلاش $retry_count برای ارسال به تلگرام ناموفق بود. خطا: $error_msg"
                sleep 2
            fi
        done
        
        if [ $success -eq 0 ]; then
            echo "❌ خطا در ارسال پیام به تلگرام پس از $max_retries تلاش: $error_msg"
            return 1
        fi
        retry_count=0  # ریست کردن برای بخش بعدی
    done
    return 0
}

# بررسی موفقیت عملیات و گزارش‌دهی
check_success() {
    local action="$1"
    local service="$2"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    if [ $? -eq 0 ]; then
        echo "[$timestamp] ✅ $action"
        send_telegram "✅ $action"
        [ -n "$service" ] && SERVICE_STATUS["$service"]="فعال"
        return 0
    else
        echo "[$timestamp] ❌ $action"
        send_telegram "⚠️ خطا در: $action"
        [ -n "$service" ] && SERVICE_STATUS["$service"]="خطا"
        return 1
    fi
}

# =============================================
# توابع اصلی (Main Functions)
# =============================================

# نصب و پیکربندی CrowdSec
install_crowdsec() {
    echo "🔄 نصب CrowdSec با محافظت کامل..."
    
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
    apt install -y crowdsec || { echo "❌ خطا در نصب CrowdSec"; return 1; }
    
    local collections=(
        "crowdsecurity/sshd" "crowdsecurity/apache2" "crowdsecurity/nginx"
        "crowdsecurity/postfix" "crowdsecurity/linux" "crowdsecurity/http-cve"
        "crowdsecurity/wordpress" "crowdsecurity/mysql"
    )
    
    for collection in "${collections[@]}"; do
        echo "   🔄 نصب مجموعه $collection..."
        cscli collections install "$collection" || echo "   ⚠️ خطا در نصب $collection"
    done
    
    cscli parsers install crowdsecurity/whitelists
    cscli scenarios install crowdsecurity/http-probing
    
    systemctl enable --now crowdsec
    sleep 5
    
    if systemctl is-active --quiet crowdsec && cscli metrics >/dev/null 2>&1; then
        check_success "نصب و راه‌اندازی CrowdSec" "crowdsec"
    else
        echo "❌ خطا در راه‌اندازی CrowdSec"
        SERVICE_STATUS["crowdsec"]="خطا"
        return 1
    fi
}

# اتصال به کنسول CrowdSec
connect_to_console() {
    echo "🔄 اتصال به کنسول CrowdSec..."
    local output=$(cscli console enroll -e "$CROWD_SEC_ENROLLMENT_TOKEN" 2>&1)
    local status=$?
    
    if [ $status -eq 0 ]; then
        SERVICE_STATUS["crowdsec_console"]="✅ متصل"
        send_telegram "🎉 **اتصال به کنسول CrowdSec با موفقیت انجام شد**  
- ایمیل: \`$CROWD_SEC_EMAIL\`  
- داشبورد: [مشاهده آلرت‌ها](https://app.crowdsec.net/alerts)  
- وضعیت: اتصال فعال"
        return 0
    else
        SERVICE_STATUS["crowdsec_console"]="❌ خطا"
        send_telegram "⚠️ **خطا در اتصال به کنسول CrowdSec**  
- ایمیل: \`$CROWD_SEC_EMAIL\`  
- خطا: \`${output:0:200}\`"
        return 1
    fi
}

# پیکربندی کاربر SFTP
configure_sftp() {
    echo "🔄 ایجاد و پیکربندی کاربر SFTP..."
    
    if id "$SFTP_USER" &>/dev/null; then
        echo "⚠️ کاربر $SFTP_USER از قبل وجود دارد"
        send_telegram "⚠️ کاربر SFTP از قبل وجود دارد"
    else
        useradd -m -s /usr/sbin/nologin "$SFTP_USER" && \
        echo "$SFTP_USER:$SFTP_PASSWORD" | chpasswd && \
        mkdir -p "/home/$SFTP_USER/.ssh" && \
        echo "$PUBLIC_KEY" > "/home/$SFTP_USER/.ssh/authorized_keys" && \
        chown -R "$SFTP_USER:$SFTP_USER" "/home/$SFTP_USER/.ssh" && \
        chmod 700 "/home/$SFTP_USER/.ssh" && \
        chmod 600 "/home/$SFTP_USER/.ssh/authorized_keys"
        
        check_success "ایجاد کاربر SFTP" "sftp_user" || return 1
    fi

    echo "🔒 تنظیمات امنیتی SFTP..."
    if ! grep -q "Subsystem sftp" /etc/ssh/sshd_config; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
        
        cat <<EOL >> /etc/ssh/sshd_config
# ======== SFTP Configuration ========
Subsystem sftp internal-sftp
Match User $SFTP_USER
    ForceCommand internal-sftp -d /upload
    PasswordAuthentication yes
    PubkeyAuthentication yes
    AuthenticationMethods publickey,password
    ChrootDirectory %h
    PermitTunnel no
    AllowAgentForwarding no
    AllowTcpForwarding no
    X11Forwarding no
EOL

        chown root:root /home/$SFTP_USER
        chmod 755 /home/$SFTP_USER
        mkdir -p /home/$SFTP_USER/upload
        chown $SFTP_USER:$SFTP_USER /home/$SFTP_USER/upload
        
        systemctl restart sshd
        check_success "تنظیمات امنیتی SFTP" "sftp_config"
    else
        echo "✅ تنظیمات SFTP از قبل اعمال شده است"
    fi
}

# ریستارت سرویس‌ها و کانتینرها
restart_services() {
    echo "🔄 ریستارت سرویس‌ها و کانتینرها..."
    
    local system_services=("docker" "code-server@$NEW_USER.service" "netdata" "crowdsec" "ssh")
    local docker_containers=("portainer" "nginx-proxy-manager")
    local RESTART_REPORT="🔄 **گزارش ریستارت سرویس‌ها:**\n"
    
    for service in "${system_services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            systemctl restart "$service"
            RESTART_REPORT+="   - $service: ✅ ریستارت شد\n"
        else
            RESTART_REPORT+="   - $service: ❌ غیرفعال\n"
        fi
    done
    
    for container in "${docker_containers[@]}"; do
        if docker ps -a --format '{{.Names}}' | grep -q "$container"; then
            docker restart "$container"
            RESTART_REPORT+="   - $container (Docker): ✅ ریستارت شد\n"
        else
            RESTART_REPORT+="   - $container (Docker): ❌ یافت نشد\n"
        fi
    done
    
    send_telegram "$RESTART_REPORT"
}

# تولید گزارش CrowdSec
generate_crowdsec_report() {
    local report="🛡️ *گزارش امنیتی CrowdSec*\n\n"
    
    # آمار تحلیل لاگ‌ها
    report+="📊 *آمار تحلیل لاگ‌ها:*\n"
    local log_stats=$(sudo cscli metrics | awk -F'│' '
        /file:\/var\/log/ {
            gsub(/^[ \t]+|[ \t]+$/, "", $1);
            gsub(/^[ \t]+|[ \t]+$/, "", $2);
            if ($2 ~ /^[0-9]+$/) {
                gsub("_", "\\_", $1);
                print "▪️ `" $1 "`: " $2 " خط"
            }
        }')
    
    [ -n "$log_stats" ] && report+="$log_stats\n" || report+="▪️ اطلاعاتی یافت نشد\n"
    
    # تصمیمات امنیتی
    report+="\n🔒 *تصمیمات امنیتی اخیر:*\n"
    local decisions=$(sudo cscli decisions list -o json | jq -r '
        group_by(.reason) | map({
            reason: .[0].reason,
            count: length,
            ips: (map(.value) | unique | join(", "))
        })[] | "▪️ " + (.reason | gsub("_"; "\\_")) + ": " + (.count | tostring) + " مورد (IPها: " + (.ips | gsub("_"; "\\_")) + ")"')
    
    if [ -n "$decisions" ]; then
        report+="$decisions\n"
    else
        report+="▪️ موردی یافت نشد\n"
    fi
    
    echo "$report"
}

# اعمال تنظیمات امنیتی سیستم
configure_security() {
    echo "🔄 اعمال تنظیمات امنیتی..."
    rm -f /etc/sysctl.d/99-server-security.conf
    cat <<EOL > /etc/sysctl.d/99-server-security.conf
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
kernel.yama.ptrace_scope=1
EOL
    
    sysctl -p /etc/sysctl.d/99-server-security.conf
    check_success "اعمال تنظیمات امنیتی"
}

# تولید گزارش نهایی
generate_final_report() {
    echo "🔄 آماده‌سازی گزارش نهایی..."
    
    local SERVER_IP=$(curl -4 -s ifconfig.me || echo "نامشخص")
    local SERVER_IP_ESCAPED=$(escape_markdown "$SERVER_IP")
    local LOCATION=$(curl -s "http://ip-api.com/line/$SERVER_IP?fields=country,city,isp" | paste -sd ' ' - || echo "نامشخص")
    local CROWD_SEC_REPORT=$(generate_crowdsec_report)
    
    local SERVICES_INFO=""
    if [ "${SERVICE_STATUS["portainer"]}" == "فعال" ]; then
        SERVICES_INFO+="▪️ [Portainer](http://${SERVER_IP_ESCAPED}:${PORTAINER_PORT})\n"
    fi
    if [ "${SERVICE_STATUS["nginx-proxy-manager"]}" == "فعال" ]; then
        SERVICES_INFO+="▪️ [Nginx Proxy Manager](http://${SERVER_IP_ESCAPED}:${NGINX_PROXY_MANAGER_PORT})\n"
    fi
    if [ "${SERVICE_STATUS["code-server"]}" == "فعال" ]; then
        SERVICES_INFO+="▪️ [Code-Server](http://${SERVER_IP_ESCAPED}:${CODE_SERVER_PORT})\n"
    fi
    if [ "${SERVICE_STATUS["netdata"]}" == "فعال" ]; then
        SERVICES_INFO+="▪️ [Netdata](http://${SERVER_IP_ESCAPED}:${NETDATA_PORT})\n"
    fi

    local FINAL_REPORT="*🚀 گزارش نهایی پیکربندی سرور*\n\n"
    FINAL_REPORT+="🕒 *زمان:* $(date +"%Y/%m/%d %H:%M:%S")\n"
    FINAL_REPORT+="🌍 *IP:* \`${SERVER_IP_ESCAPED}\`\n"
    FINAL_REPORT+="📍 *موقعیت:* ${LOCATION}\n"
    FINAL_REPORT+="🖥️ *میزبان:* \`$(hostname)\`\n\n"
    
    FINAL_REPORT+="🔑 *دسترسی‌های اصلی:*\n"
    FINAL_REPORT+="▪️ کاربر اصلی: \`${NEW_USER}\`\n"
    FINAL_REPORT+="▪️ پورت SSH: \`${SSH_PORT}\`\n"
    FINAL_REPORT+="▪️ کاربر SFTP: \`${SFTP_USER}\`\n\n"
    
    FINAL_REPORT+="${CROWD_SEC_REPORT}\n"
    
    FINAL_REPORT+="🛠️ *سرویس‌های نصب‌شده:*\n"
    if [ -n "$SERVICES_INFO" ]; then
        FINAL_REPORT+="$SERVICES_INFO\n"
    else
        FINAL_REPORT+="▪️ هیچ سرویس فعالی وجود ندارد\n"
    fi
    
    FINAL_REPORT+="🔒 *وضعیت امنیتی:*\n"
    FINAL_REPORT+="▪️ فایروال: فعال\n"
    FINAL_REPORT+="▪️ آخرین بروزرسانی: $(date +"%Y/%m/%d %H:%M")\n"
    FINAL_REPORT+="▪️ [مشاهده آلرت‌ها در کنسول CrowdSec](https://app\.crowdsec\.net/alerts)\n"
    
    send_telegram "$FINAL_REPORT"
    echo "✅ گزارش نهایی ارسال شد"
}

# =============================================
# نصب و بررسی jq (JQ Installer)
# =============================================
install_jq() {
    echo "🔄 بررسی وجود jq در سیستم..."
    
    if command -v jq &>/dev/null; then
        echo "✅ jq از قبل نصب شده است (ورژن: $(jq --version))"
        return 0
    fi
    
    echo "📦 در حال نصب jq..."
    
    # تشخیص توزیع لینوکس برای نصب صحیح
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        case $ID in
            debian|ubuntu)
                apt update && apt install -y jq
                ;;
            centos|rhel|fedora)
                yum install -y jq
                ;;
            alpine)
                apk add jq
                ;;
            *)
                # نصب از سورس برای توزیع‌های ناشناخته
                curl -L -o /usr/local/bin/jq https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64
                chmod +x /usr/local/bin/jq
                ;;
        esac
    else
        # روش fallback اگر /etc/os-release وجود نداشت
        curl -L -o /usr/local/bin/jq https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64
        chmod +x /usr/local/bin/jq
    fi
    
    # بررسی نصب موفق
    if command -v jq &>/dev/null; then
        echo "✅ jq با موفقیت نصب شد (ورژن: $(jq --version))"
        return 0
    else
        echo "❌ خطا در نصب jq"
        return 1
    fi
}

# =============================================
# تابع اصلی (Main Function)
# =============================================
main() {
    # ------------------------------
    # بخش ۱: گزارش شروع و آماده‌سازی اولیه
    # ------------------------------
    local START_TIME=$(date +"%s")
    local SERVER_IP=$(curl -4 -s ifconfig.me || echo "نامشخص")
    local LOCATION=$(curl -s "http://ip-api.com/line/$SERVER_IP?fields=country,city,isp" | paste -sd ' ' - || echo "نامشخص")
    
    # گزارش شروع با فرمت MarkdownV2
    local START_REPORT=$(cat <<EOF
*🚀 شروع فرآیند پیکربندی سرور*

▫️ *زمان:* $(date +"%Y/%m/%d %H:%M:%S")
▫️ *IP سرور:* \`${SERVER_IP}\`
▫️ *موقعیت:* ${LOCATION}
▫️ *کاربر اصلی:* \`${NEW_USER}\`
▫️ *پورت SSH:* \`${SSH_PORT}\`
▫️ *نسخه هسته:* \`$(uname -r)\`
EOF
    )
    send_telegram "$START_REPORT"

    # ------------------------------
    # بخش ۲: نصب پیش‌نیازها
    # ------------------------------
    send_telegram "*🔧 در حال نصب پیش‌نیازها...*"
    
    # نصب jq با گزارش‌دهی دقیق
    if install_jq; then
        send_telegram "✅ *نصب jq موفقیت‌آمیز بود* \nورژن: \`$(jq --version)\`"
    else
        send_telegram "⚠️ *هشدار: نصب jq ناموفق بود* \nبرخی ویژگی‌های پیشرفته غیرفعال خواهند بود"
    fi

    # ------------------------------
    # بخش ۳: به‌روزرسانی سیستم
    # ------------------------------
    send_telegram "*🔄 در حال به‌روزرسانی سیستم...*"
    apt update && apt upgrade -y
    check_success "به‌روزرسانی سیستم" || {
        send_telegram "❌ *خطای بحرانی: به‌روزرسانی سیستم ناموفق بود* \nفرآیند متوقف شد!"
        exit 1
    }

    # ------------------------------
    # بخش ۴: ایجاد کاربر اصلی
    # ------------------------------
    send_telegram "*👤 در حال ایجاد کاربر اصلی...*"
    if id "$NEW_USER" &>/dev/null; then
        send_telegram "ℹ️ کاربر \`${NEW_USER}\` از قبل وجود دارد \nتنظیمات احراز هویت اعمال می‌شود"
    else
        adduser --disabled-password --gecos "" "$NEW_USER" && \
        usermod -aG sudo "$NEW_USER" && \
        echo "$NEW_USER ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/"$NEW_USER" && \
        mkdir -p "/home/$NEW_USER/.ssh" && \
        echo "$PUBLIC_KEY" > "/home/$NEW_USER/.ssh/authorized_keys" && \
        chown -R "$NEW_USER:$NEW_USER" "/home/$NEW_USER/.ssh" && \
        chmod 700 "/home/$NEW_USER/.ssh" && \
        chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"
        
        check_success "ایجاد و تنظیم کاربر $NEW_USER" || exit 1
        send_telegram "✅ کاربر \`${NEW_USER}\` با موفقیت ایجاد شد \nکلید SSH تنظیم شد"
    fi

    # ------------------------------
    # بخش ۵: تنظیمات امنیتی پایه
    # ------------------------------
    send_telegram "*🔒 در حال اعمال تنظیمات امنیتی پایه...*"
    
    # ۵.۱ تنظیمات SSH
    configure_ssh
    
    # ۵.۲ پیکربندی SFTP
    configure_sftp
    
    # ۵.۳ تنظیمات فایروال
    configure_firewall
    
    # ۵.۴ تنظیمات امنیتی سیستم
    configure_security

    # ------------------------------
    # بخش ۶: نصب سرویس‌های اصلی
    # ------------------------------
    send_telegram "*🛠️ در حال نصب سرویس‌های اصلی...*"
    
    # ۶.۱ نصب Docker
    install_docker
    
    # ۶.۲ نصب Portainer
    install_portainer
    
    # ۶.۳ نصب Nginx Proxy Manager
    install_nginx_proxy_manager
    
    # ۶.۴ نصب Netdata
    install_netdata
    
    # ۶.۵ نصب CrowdSec
    install_crowdsec
    
    # ۶.۶ نصب Code-Server
    install_code_server

    # ------------------------------
    # بخش ۷: نصب ابزارهای جانبی
    # ------------------------------
    send_telegram "*📦 در حال نصب ابزارهای کمکی...*"
    apt install -y \
        wget curl net-tools iperf3 \
        htop glances tmux \
        rsync vim nano unzip zip \
        build-essential git lftp \
        clamav clamav-daemon rkhunter lynis \
        auditd tcpdump nmap \
        python3-pip python3-venv python3-dev
        
    systemctl enable --now auditd
    check_success "نصب ابزارهای جانبی"

    # ------------------------------
    # بخش ۸: راه‌اندازی نهایی
    # ------------------------------
    send_telegram "*⚡ در حال انجام تنظیمات نهایی...*"
    
    # ۸.۱ ریستارت سرویس‌ها
    restart_services
    
    # ۸.۲ اتصال به کنسول CrowdSec
    connect_to_console
    
    # ۸.۳ تولید گزارش نهایی
    generate_final_report

    # ------------------------------
    # بخش ۹: گزارش پایانی
    # ------------------------------
    local END_TIME=$(date +"%s")
    local DURATION=$((END_TIME - START_TIME))
    local MINUTES=$((DURATION / 60))
    local SECONDS=$((DURATION % 60))
    
    send_telegram "*🎉 پیکربندی سرور با موفقیت تکمیل شد!* \n⏱️ زمان اجرا: ${MINUTES} دقیقه و ${SECONDS} ثانیه"
    echo "✅ پیکربندی سرور در ${MINUTES} دقیقه و ${SECONDS} ثانیه تکمیل شد"
}

# اجرای تابع اصلی
main "$@"
exit 0
