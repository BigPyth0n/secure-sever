#!/bin/bash

# =============================================
# تنظیمات اصلی
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

# لیست پورت‌های باز
PORTS_TO_OPEN=("80" "443" "$SSH_PORT" "$CODE_SERVER_PORT" "$NETDATA_PORT" "$WAZUH_DASHBOARD_PORT" "$PORTAINER_PORT" "$NGINX_PROXY_MANAGER_PORT")
RESERVED_PORTS=("1020" "1030" "1040" "2060" "3050" "2020" "4040" "3060" "2080")

# آرایه برای ذخیره وضعیت سرویس‌ها
declare -A SERVICE_STATUS

# =============================================
# توابع کمکی بهبود یافته
# =============================================

# تابع ارسال گزارش به تلگرام با کنترل خطا
send_telegram() {
    local message="$1"
    local max_retries=3
    local retry_count=0
    local success=0
    
    while [ $retry_count -lt $max_retries ]; do
        response=$(curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
            -d "chat_id=$TELEGRAM_CHAT_ID" \
            -d "text=$message" \
            -d "parse_mode=Markdown" 2>&1)
        
        if [[ $response == *"\"ok\":true"* ]]; then
            success=1
            break
        else
            retry_count=$((retry_count+1))
            sleep 2
        fi
    done
    
    if [ $success -eq 0 ]; then
        echo "⚠️ خطا در ارسال پیام به تلگرام پس از $max_retries تلاش"
        echo "پیام خطا: $response"
    fi
}

# تابع بررسی موفقیت عملیات با لاگ‌گیری پیشرفته
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
# تابع نصب امن CrowdSec
# =============================================
install_crowdsec() {
    echo "🔄 نصب CrowdSec با محافظت کامل..."
    
    # نصب از منابع رسمی
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
    apt install -y crowdsec || return 1
    
    # نصب تمام مجموعه‌های محافظتی
    local collections=(
        "crowdsecurity/sshd"
        "crowdsecurity/apache2"
        "crowdsecurity/nginx"
        "crowdsecurity/postfix"
        "crowdsecurity/linux"
        "crowdsecurity/http-cve"
        "crowdsecurity/wordpress"
        "crowdsecurity/mysql"
    )
    
    for collection in "${collections[@]}"; do
        echo "   🔄 نصب مجموعه $collection..."
        cscli collections install "$collection" || echo "   ⚠️ خطا در نصب $collection"
    done
    
    # تنظیمات سفارشی
    cscli parsers install crowdsecurity/whitelists
    cscli scenarios install crowdsecurity/http-probing
    
    # راه‌اندازی سرویس
    systemctl enable --now crowdsec
    sleep 5
    
    # بررسی نهایی
    if systemctl is-active --quiet crowdsec && cscli metrics >/dev/null 2>&1; then
        echo "✅ CrowdSec با موفقیت نصب و پیکربندی شد"
        SERVICE_STATUS["crowdsec"]="فعال"
        return 0
    else
        echo "❌ خطا در راه‌اندازی CrowdSec"
        SERVICE_STATUS["crowdsec"]="خطا"
        return 1
    fi
}

# =============================================
# تابع اتصال به CrowdSec Console
# =============================================
connect_to_console() {
    echo "🔄 Connecting to CrowdSec Console..."
    local output=$(sudo cscli console enroll -e context cm8qh5k6b0007iacrx07s382h 2>&1)
    local status=$?
    
    if [ $status -eq 0 ]; then
        SERVICE_STATUS["crowdsec_console"]="✅ Active"
        send_telegram "🎉 *CrowdSec Console Connection Successful*"
        return 0
    else
        SERVICE_STATUS["crowdsec_console"]="❌ Failed"
        send_telegram "⚠️ *CrowdSec Console Connection Failed*"
        return 1
    fi
}

# =============================================
# تابع پیکربندی امن SFTP
# =============================================
configure_sftp() {
    echo "🔄 Creating SFTP user: $SFTP_USER..."
    
    if id "$SFTP_USER" &>/dev/null; then
        echo "⚠️ User $SFTP_USER already exists"
        send_telegram "⚠️ کاربر SFTP از قبل وجود دارد"
    else
        # ایجاد کاربر با دسترسی محدود
        useradd -m -s /usr/sbin/nologin "$SFTP_USER" && \
        echo "$SFTP_USER:$SFTP_PASSWORD" | chpasswd && \
        mkdir -p "/home/$SFTP_USER/.ssh" && \
        echo "$PUBLIC_KEY" > "/home/$SFTP_USER/.ssh/authorized_keys" && \
        chown -R "$SFTP_USER:$SFTP_USER" "/home/$SFTP_USER/.ssh" && \
        chmod 700 "/home/$SFTP_USER/.ssh" && \
        chmod 600 "/home/$SFTP_USER/.ssh/authorized_keys"
        
        check_success "ایجاد کاربر SFTP" "sftp_user" || return 1
    fi

    # پیکربندی SSH برای SFTP
    echo "🔒 Configuring Secure SFTP..."
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

        # تنظیم مجوزها
        chown root:root /home/$SFTP_USER
        chmod 755 /home/$SFTP_USER
        mkdir -p /home/$SFTP_USER/upload
        chown $SFTP_USER:$SFTP_USER /home/$SFTP_USER/upload
        
        systemctl restart sshd
        check_success "تنظیمات امنیتی SFTP" "sftp_config"
    else
        echo "✅ SFTP configuration already exists"
    fi
}

# =============================================
# تابع گزارش‌دهی CrowdSec بهینه‌شده
# =============================================
generate_crowdsec_report() {
    local report="
🛡️ **گزارش امنیتی CrowdSec:**  
📊 **آمار تحلیل لاگ‌ها:**  
"
    
    # تحلیل لاگ‌ها
    log_stats=$(cscli metrics | awk '/file:\/var\/log\// {print "   - " $1 ": " $3 " خط"}')
    report+="${log_stats:-"   - هیچ لاگی تحلیل نشده"}\n\n"
    
    # تصمیمات امنیتی
    report+="🔒 **تصمیمات امنیتی اخیر:**\n"
    decisions=$(cscli metrics | awk '/ban/ {print "   - " $1 ": " $4 " مورد"}')
    report+="${decisions:-"   - هیچ حمله‌ای شناسایی نشد"}\n"
    
    echo "$report"
}

# =============================================
# تابع گزارش نهایی
# =============================================
generate_final_report() {
    SERVER_IP=$(curl -s ifconfig.me || echo "نامشخص")
    LOCATION=$(curl -s http://ip-api.com/line/$SERVER_IP?fields=country,city,isp || echo "نامشخص")
    CROWD_SEC_REPORT=$(generate_crowdsec_report)
    
    FINAL_REPORT="
🚀 **گزارش نهایی پیکربندی سرور**  
⏳ زمان: $(date +"%Y-%m-%d %H:%M:%S")  

🔹 **مشخصات سرور:**  
   - IP: \`$SERVER_IP\`  
   - موقعیت: $LOCATION  
   - میزبان: \`$(hostname)\`  

🔹 **دسترسی‌های اصلی:**  
   - کاربر اصلی: \`$NEW_USER\`  
   - SSH Port: \`$SSH_PORT\` (فقط کلید عمومی)  
   - کاربر SFTP: \`$SFTP_USER\`  
   - رمز SFTP: \`$SFTP_PASSWORD\`  
   - پورت‌های باز: ${PORTS_TO_OPEN[*]}  

${CROWD_SEC_REPORT}

🔹 **سرویس‌های نصب شده:**  
   - Portainer: [لینک](http://$SERVER_IP:$PORTAINER_PORT)  
   - Nginx Proxy Manager: [لینک](http://$SERVER_IP:$NGINX_PROXY_MANAGER_PORT)  
   - Code-Server: [لینک](http://$SERVER_IP:$CODE_SERVER_PORT)  
   - Netdata: [لینک](http://$SERVER_IP:$NETDATA_PORT)  

🔐 **وضعیت امنیتی:**  
   - فایروال: ✅ فعال  
   - CrowdSec: ${SERVICE_STATUS["crowdsec"]}  
   - آخرین بروزرسانی: $(date +"%Y-%m-%d %H:%M")  
"
    
    send_telegram "$FINAL_REPORT"
    echo "✅ گزارش نهایی ارسال شد"
}

# =============================================
# شروع فرآیند نصب
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

main "$@"
exit 0
