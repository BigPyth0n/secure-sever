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
    
    # اسکیپ کردن تمام کاراکترهای خاص برای MarkdownV2
    message=$(echo "$message" | sed -e 's/[][_*()~`>#+=|{}.!]/\\&/g')
    
    # تقسیم پیام به بخش‌های 4096 کاراکتری
    local parts=()
    while [ -n "$message" ]; do
        if [ ${#message} -le 4096 ]; then
            parts+=("$message")
            message=""
        else
            local part="${message:0:4096}"
            local last_line=$(echo "$part" | grep -o '[^\n]*$')
            if [ "$last_line" != "$part" ]; then
                part=$(echo "$part" | sed '$d')
                message="${message:${#part}}"
            else
                parts+=("$part")
                message="${message:4096}"
            fi
        fi
    done
    
    for part in "${parts[@]}"; do
        retry_count=0
        success=0
        while [ $retry_count -lt $max_retries ]; do
            response=$(curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
                -d "chat_id=$TELEGRAM_CHAT_ID" \
                -d "text=$part" \
                -d "parse_mode=MarkdownV2" \
                -d "disable_web_page_preview=true" 2>&1)
            
            if echo "$response" | grep -q '"ok":true'; then
                success=1
                break
            else
                retry_count=$((retry_count + 1))
                error_msg=$(echo "$response" | grep -o '"description":"[^"]*"' | cut -d'"' -f4 || echo "$response")
                echo "⚠️ تلاش $retry_count برای ارسال بخش پیام ناموفق بود. خطا: $error_msg"
                sleep 2
            fi
        done
        
        if [ $success -eq 0 ]; then
            echo "❌ خطا در ارسال بخش پیام پس از $max_retries تلاش: $error_msg"
            return 1
        fi
    done
    
    echo "✅ تمام بخش‌های پیام با موفقیت ارسال شدند"
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
    local report="📊 *گزارش امنیتی CrowdSec*\n\n"
    
    # آمار تحلیل لاگ‌ها
    report+="🔍 *آمار تحلیل لاگ‌ها:*\n"
    local log_stats=$(sudo cscli metrics --no-color | awk -F'│' '
        /file:\/var\/log/ {
            gsub(/^[ \t]+|[ \t]+$/, "", $1);
            gsub(/^[ \t]+|[ \t]+$/, "", $2);
            if ($2 ~ /^[0-9]+$/) {
                printf("▪️ `%s`: %d خط\n", $1, $2);
            }
        }' | sed 's/_/\\_/g' | sed 's/\./\\./g')
    
    [ -n "$log_stats" ] && report+="$log_stats\n" || report+="▪️ اطلاعاتی یافت نشد\n"
    
    # تصمیمات امنیتی
    report+="\n🛡️ *تصمیمات امنیتی اخیر:*\n"
    local decisions=$(sudo cscli decisions list --no-color -o json | jq -r '
        group_by(.reason) | map({
            reason: .[0].reason,
            count: length,
            ips: (map(.value) | unique | join(", "))
        })[] | "▪️ \(.reason): \(.count) مورد (IPها: \(.ips))"' 2>/dev/null | sed 's/_/\\_/g' | sed 's/\./\\./g')
    
    if [ -n "$decisions" ]; then
        report+="$decisions\n"
    else
        report+="▪️ موردی یافت نشد\n"
    fi
    
    # وضعیت کلی
    report+="\n📈 *وضعیت کلی:*\n"
    local metrics=$(sudo cscli metrics --no-color | awk -F'│' '
        /Parsers:/ { printf("▪️ پارسرها: %s\n", $2) }
        /Scenarios:/ { printf("▪️ سناریوها: %s\n", $2) }
        /Collections:/ { printf("▪️ مجموعه‌ها: %s\n", $2) }
    ' | sed 's/_/\\_/g')
    report+="$metrics"
    
    echo -e "$report"
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
    local LOCATION=$(curl -s "http://ip-api.com/line/$SERVER_IP?fields=country,city,isp" | paste -sd ' ' - || echo "نامشخص")
    local CROWD_SEC_REPORT=$(generate_crowdsec_report)
    
    # اسکیپ کردن IP برای MarkdownV2
    local SERVER_IP_ESCAPED=$(echo "$SERVER_IP" | sed 's/\./\\./g')
    
    local SERVICES_INFO=""
    if [ "${SERVICE_STATUS["portainer"]}" == "فعال" ]; then
        SERVICES_INFO+="▪️ \[Portainer\]\(http://${SERVER_IP_ESCAPED}:${PORTAINER_PORT}\)\n"
    fi
    if [ "${SERVICE_STATUS["nginx-proxy-manager"]}" == "فعال" ]; then
        SERVICES_INFO+="▪️ \[Nginx Proxy Manager\]\(http://${SERVER_IP_ESCAPED}:${NGINX_PROXY_MANAGER_PORT}\)\n"
    fi
    if [ "${SERVICE_STATUS["code-server"]}" == "فعال" ]; then
        SERVICES_INFO+="▪️ \[Code-Server\]\(http://${SERVER_IP_ESCAPED}:${CODE_SERVER_PORT}\)\n"
    fi
    if [ "${SERVICE_STATUS["netdata"]}" == "فعال" ]; then
        SERVICES_INFO+="▪️ \[Netdata\]\(http://${SERVER_IP_ESCAPED}:${NETDATA_PORT}\)\n"
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
    FINAL_REPORT+="▪️ \[مشاهده آلرت‌ها در کنسول CrowdSec\]\(https://app\.crowdsec\.net/alerts\)\n"
    
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
    # گزارش شروع
    START_REPORT="
🔥 **شروع فرآیند پیکربندی سرور**  
🕒 زمان: $(date +"%Y-%m-%d %H:%M:%S")  
🌍 IP: $(curl -s ifconfig.me || echo "نامشخص")  
📌 کاربر اصلی: $NEW_USER  
🔒 پورت SSH: $SSH_PORT  
"
    send_telegram "$START_REPORT"

    # 1. به‌روزرسانی سیستم
    echo "🔄 در حال بروزرسانی سیستم..."
    apt update && apt upgrade -y
    check_success "بروزرسانی سیستم انجام شد" || exit 1

    # 2. ایجاد کاربر اصلی
    echo "🔄 ایجاد کاربر $NEW_USER..."
    if id "$NEW_USER" &>/dev/null; then
        echo "⚠️ کاربر $NEW_USER از قبل وجود دارد"
    else
        adduser --disabled-password --gecos "" "$NEW_USER" && \
        usermod -aG sudo "$NEW_USER" && \
        echo "$NEW_USER ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/"$NEW_USER" && \
        mkdir -p "/home/$NEW_USER/.ssh" && \
        echo "$PUBLIC_KEY" > "/home/$NEW_USER/.ssh/authorized_keys" && \
        chown -R "$NEW_USER":"$NEW_USER" "/home/$NEW_USER/.ssh" && \
        chmod 700 "/home/$NEW_USER/.ssh" && \
        chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"
    fi
    check_success "تنظیمات کاربر $NEW_USER"

    # 3. تنظیمات SSH
    echo "🔄 تنظیمات امنیتی SSH..."
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    cat <<EOL > /etc/ssh/sshd_config
Port $SSH_PORT
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
AuthenticationMethods publickey
AllowUsers $NEW_USER $SFTP_USER
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
EOL
    systemctl restart sshd
    check_success "تنظیمات SSH" "ssh"

    # 4. پیکربندی SFTP
    configure_sftp

    # 5. نصب Docker
    echo "🔄 نصب Docker و Docker Compose..."
    if ! command -v docker &>/dev/null; then
        apt install -y apt-transport-https ca-certificates curl software-properties-common && \
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
        add-apt-repository -y "deb [arch=amd64] https://download.docker.com/linux/ubuntu jammy stable" && \
        apt update && apt install -y docker-ce docker-ce-cli containerd.io && \
        systemctl enable --now docker && \
        usermod -aG docker "$NEW_USER" && \
        curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose && \
        chmod +x /usr/local/bin/docker-compose
        check_success "نصب Docker و Docker Compose" "docker"
    else
        echo "✅ Docker از قبل نصب شده است"
        SERVICE_STATUS["docker"]="فعال"
    fi

    # 6. نصب Portainer
    echo "🔄 نصب Portainer..."
    if ! docker ps -a --format '{{.Names}}' | grep -q 'portainer'; then
        docker volume create portainer_data && \
        docker run -d --name portainer -p "$PORTAINER_PORT:9000" \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v portainer_data:/data \
            --restart unless-stopped \
            portainer/portainer-ce:latest
        check_success "نصب Portainer" "portainer"
    else
        echo "✅ Portainer از قبل نصب شده است"
        SERVICE_STATUS["portainer"]="فعال"
    fi

    # 7. نصب Nginx Proxy Manager
    echo "🔄 نصب Nginx Proxy Manager..."
    if ! docker ps -a --format '{{.Names}}' | grep -q 'nginx-proxy-manager'; then
        mkdir -p /var/docker/nginx-proxy-manager/{data,letsencrypt} && \
        docker run -d \
            --name nginx-proxy-manager \
            -p 80:80 \
            -p 443:443 \
            -p "$NGINX_PROXY_MANAGER_PORT:81" \
            -v /var/docker/nginx-proxy-manager/data:/data \
            -v /var/docker/nginx-proxy-manager/letsencrypt:/etc/letsencrypt \
            --restart unless-stopped \
            jc21/nginx-proxy-manager:latest
        check_success "نصب Nginx Proxy Manager" "nginx-proxy-manager"
    else
        echo "✅ Nginx Proxy Manager از قبل نصب شده است"
        SERVICE_STATUS["nginx-proxy-manager"]="فعال"
    fi

    # 8. نصب Netdata
    echo "🔄 نصب Netdata..."
    if ! systemctl is-active --quiet netdata; then
        apt purge -y netdata netdata-core netdata-web netdata-plugins-bash && \
        rm -rf /etc/netdata /usr/share/netdata /var/lib/netdata && \
        wget -O /tmp/netdata-kickstart.sh https://my-netdata.io/kickstart.sh && \
        bash /tmp/netdata-kickstart.sh --stable-channel --disable-telemetry && \
        tee /etc/netdata/netdata.conf <<EOL
[global]
    run as user = netdata
[web]
    bind to = 0.0.0.0:$NETDATA_PORT
    allow connections from = *
    web files owner = netdata
    web files group = netdata
    mode = static-threaded
EOL
        chown -R netdata:netdata /usr/share/netdata/web && \
        chmod -R 0755 /usr/share/netdata/web && \
        systemctl restart netdata
        check_success "نصب Netdata" "netdata"
    else
        echo "✅ Netdata از قبل نصب شده است"
        SERVICE_STATUS["netdata"]="فعال"
    fi

    # 9. نصب CrowdSec
    install_crowdsec

    # 10. تنظیم فایروال
    echo "🔄 تنظیم فایروال..."
    if ! command -v ufw &>/dev/null; then
        apt install -y ufw
    fi

    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    for port in "${PORTS_TO_OPEN[@]}"; do
        ufw allow "$port/tcp"
        echo "   🔓 پورت $port/tcp باز شد"
    done

    ufw --force enable
    check_success "تنظیم فایروال" "ufw"

    # 11. نصب Code-Server
    echo "🔄 نصب Code-Server..."
    if ! command -v code-server &>/dev/null; then
        curl -fsSL https://code-server.dev/install.sh | sh && \
        setcap cap_net_bind_service=+ep /usr/lib/code-server/lib/node && \
        systemctl enable --now code-server@"$NEW_USER" && \
        mkdir -p "/home/$NEW_USER/.config/code-server" && \
        cat <<EOL > "/home/$NEW_USER/.config/code-server/config.yaml"
bind-addr: 0.0.0.0:$CODE_SERVER_PORT
auth: password
password: $CODE_SERVER_PASSWORD
cert: false
EOL
        chown -R "$NEW_USER":"$NEW_USER" "/home/$NEW_USER/.config" && \
        systemctl restart code-server@"$NEW_USER"
        
        sleep 5
        if netstat -tuln | grep -q "$CODE_SERVER_PORT"; then
            check_success "نصب Code-Server" "code-server"
        else
            echo "❌ Code-Server روی پورت $CODE_SERVER_PORT اجرا نشد"
            SERVICE_STATUS["code-server"]="خطا"
        fi
    else
        echo "✅ Code-Server از قبل نصب شده است"
        SERVICE_STATUS["code-server"]="فعال"
    fi

    # 12. نصب ابزارهای جانبی
    echo "🔄 نصب ابزارهای جانبی..."
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

    # 13. تنظیمات امنیتی نهایی
    echo "🔄 اعمال تنظیمات امنیتی..."
    cat <<EOL >> /etc/sysctl.conf
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
    sysctl -p
    check_success "تنظیمات امنیتی اعمال شد"

    # 14. اتصال به کنسول CrowdSec
    connect_to_console

    # 15. گزارش نهایی
    generate_final_report

    echo "🎉 پیکربندی سرور با موفقیت تکمیل شد!"
}

# اجرای تابع اصلی
main "$@"
exit 0
