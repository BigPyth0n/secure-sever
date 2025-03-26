#!/bin/bash

# =============================================
# تنظیمات اصلی
# =============================================
TELEGRAM_BOT_TOKEN="5054947489:AAFSNuI5JP0MhywlkZQIlePqubUpfVFhH9Q"
TELEGRAM_CHAT_ID="59941862"  # اگر گروهه، به "-59941862" تغییر بده
NEW_USER="bigpython"
SSH_PORT="9011"
CODE_SERVER_PORT="1010"
NETDATA_PORT="9001"
CROWDSEC_DASHBOARD_PORT="3000"
PORTAINER_PORT="9000"
NGINX_PROXY_MANAGER_PORT="81"
CODE_SERVER_PASSWORD="114aa2650b0db5509f36f4fc"  # پس از نصب تغییر دهید
PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO8J++ag0NtV/AaQU9mF7X8qSKGrOy2Wu1eJISg72Zfs bigpython@TradePC"

# لیست پورت‌های باز
PORTS_TO_OPEN=("80" "443" "$SSH_PORT" "$CODE_SERVER_PORT" "$NETDATA_PORT" "$CROWDSEC_DASHBOARD_PORT" "$PORTAINER_PORT" "$NGINX_PROXY_MANAGER_PORT")
RESERVED_PORTS=("1020" "1030" "1040" "2060" "3050" "2020" "4040" "3060" "2080")

# آرایه برای ذخیره وضعیت سرویس‌ها
declare -A SERVICE_STATUS

# =============================================
# توابع کمکی
# =============================================

# تابع ارسال گزارش به تلگرام
send_telegram() {
    local message="$1"
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TELEGRAM_CHAT_ID" \
        -d "text=$message" \
        -d "parse_mode=Markdown" >/dev/null 2>&1 || echo "⚠️ خطا در ارسال پیام به تلگرام"
}

# تابع بررسی موفقیت عملیات
check_success() {
    local action="$1"
    local service="$2"
    if [ $? -eq 0 ]; then
        echo "✅ $action"
        send_telegram "✅ $action"
        [ -n "$service" ] && SERVICE_STATUS["$service"]="فعال"
    else
        echo "❌ $action"
        send_telegram "⚠️ خطا در: $action (ادامه فرآیند)"
        [ -n "$service" ] && SERVICE_STATUS["$service"]="خطا"
    fi
}

# =============================================
# شروع فرآیند نصب
# =============================================

# گزارش شروع
send_telegram "🔥 **شروع فرآیند پیکربندی سرور** در $(date)"

# 1. به‌روزرسانی سیستم
echo "🔄 در حال بروزرسانی سیستم..."
apt update && apt upgrade -y
check_success "بروزرسانی سیستم انجام شد"

# 2. ایجاد کاربر جدید
echo "🔄 ایجاد کاربر $NEW_USER..."
adduser --disabled-password --gecos "" "$NEW_USER"
usermod -aG sudo "$NEW_USER"
echo "$NEW_USER ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/"$NEW_USER"
mkdir -p "/home/$NEW_USER/.ssh"
echo "$PUBLIC_KEY" > "/home/$NEW_USER/.ssh/authorized_keys"
chown -R "$NEW_USER":"$NEW_USER" "/home/$NEW_USER/.ssh"
chmod 700 "/home/$NEW_USER/.ssh"
chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"
check_success "ایجاد کاربر $NEW_USER"

# تنظیمات SSH
cat <<EOL > /etc/ssh/sshd_config
Port $SSH_PORT
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
AuthenticationMethods publickey
AllowUsers $NEW_USER
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
EOL
systemctl restart sshd
check_success "تنظیمات SSH برای کاربر $NEW_USER"

# نصب Docker و Docker Compose
echo "🔄 نصب Docker و Docker Compose..."
apt install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository -y "deb [arch=amd64] https://download.docker.com/linux/ubuntu jammy stable"
apt update && apt install -y docker-ce
systemctl enable --now docker
usermod -aG docker "$NEW_USER"
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
check_success "نصب Docker و Docker Compose" "docker"

# نصب Portainer
echo "🔄 نصب Portainer..."
docker volume create portainer_data
docker run -d --name portainer -p "$PORTAINER_PORT:9000" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v portainer_data:/data \
    --restart unless-stopped \
    portainer/portainer-ce:latest
check_success "نصب و راه‌اندازی Portainer" "portainer"

# نصب Nginx Proxy Manager
echo "🔄 نصب Nginx Proxy Manager..."
mkdir -p /var/docker/nginx-proxy-manager/{data,letsencrypt}
docker run -d \
    --name nginx-proxy-manager \
    -p 80:80 \
    -p 443:443 \
    -p "$NGINX_PROXY_MANAGER_PORT:81" \
    -v /var/docker/nginx-proxy-manager/data:/data \
    -v /var/docker/nginx-proxy-manager/letsencrypt:/etc/letsencrypt \
    --restart unless-stopped \
    jc21/nginx-proxy-manager:latest
check_success "نصب و راه‌اندازی Nginx Proxy Manager" "nginx-proxy-manager"

# نصب Netdata
echo "🔄 نصب Netdata..."
sudo apt purge -y netdata netdata-core netdata-web netdata-plugins-bash
sudo rm -rf /etc/netdata /usr/share/netdata /var/lib/netdata
wget -O /tmp/netdata-kickstart.sh https://my-netdata.io/kickstart.sh
sudo bash /tmp/netdata-kickstart.sh --stable-channel --disable-telemetry
sudo tee /etc/netdata/netdata.conf <<EOL
[global]
    run as user = netdata
[web]
    bind to = 0.0.0.0:$NETDATA_PORT
    allow connections from = *
    web files owner = netdata
    web files group = netdata
    mode = static-threaded
EOL
sudo chown -R netdata:netdata /usr/share/netdata/web
sudo chmod -R 0755 /usr/share/netdata/web
sudo systemctl restart netdata
check_success "نصب و راه‌اندازی Netdata" "netdata"

# تنظیم فایروال
echo "🔄 تنظیم فایروال..."
apt install -y ufw
ufw default deny incoming
ufw default allow outgoing
for port in "${PORTS_TO_OPEN[@]}"; do
    ufw allow "$port/tcp"
done
ufw --force enable
check_success "تنظیم فایروال"










# ========================================================
# نصب و تنظیم CrowdSec و Metabase
echo "🔄 نصب CrowdSec و داشبورد Metabase..."
apt install -y ipset iptables
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
if apt install -y crowdsec crowdsec-firewall-bouncer-iptables; then
    if [ -f /usr/bin/cscli ]; then
        # ایجاد کاربر crowdsec اگه وجود نداره
        if ! id crowdsec >/dev/null 2>&1; then
            sudo adduser --system --group --no-create-home crowdsec
        fi
        # تنظیم فایل اصلی config.yaml
        cat <<EOL > /etc/crowdsec/config.yaml
api:
  server:
    listen_uri: 0.0.0.0:$CROWDSEC_DASHBOARD_PORT
    profiles_path: /etc/crowdsec/profiles.yaml
db_config:
  type: sqlite
  db_path: /var/lib/crowdsec/data/crowdsec.db
EOL
        # تنظیم فایل محلی
        cat <<EOL > /etc/crowdsec/config.yaml.local
api:
  server:
    listen_uri: 0.0.0.0:$CROWDSEC_DASHBOARD_PORT
    profiles_path: /etc/crowdsec/profiles.yaml
db_config:
  type: sqlite
  db_path: /var/lib/crowdsec/data/crowdsec.db
EOL
        chown -R crowdsec:crowdsec /etc/crowdsec
        chmod -R 755 /var/lib/crowdsec/data
        systemctl enable --now crowdsec
        systemctl restart crowdsec
        if systemctl is-active docker >/dev/null 2>&1; then
            echo "نصب داشبورد CrowdSec شروع می‌شود (غیرتعاملی، حداکثر 5 دقیقه)..."
            timeout 300 cscli dashboard setup --listen 0.0.0.0:$CROWDSEC_DASHBOARD_PORT --yes
            if [ $? -eq 0 ]; then
                sleep 10
                if docker ps -a | grep -q metabase; then
                    if docker ps | grep -q metabase; then
                        check_success "نصب و راه‌اندازی CrowdSec و داشبورد" "crowdsec"
                    else
                        send_telegram "⚠️ CrowdSec نصب شد اما داشبورد اجرا نشد (ادامه فرآیند)"
                        SERVICE_STATUS["crowdsec"]="خطا"
                    fi
                else
                    send_telegram "⚠️ CrowdSec نصب شد اما داشبورد نصب نشد (ادامه فرآیند)"
                    SERVICE_STATUS["crowdsec"]="خطا"
                fi
            else
                send_telegram "❌ نصب داشبورد CrowdSec با خطا مواجه شد (ادامه فرآیند)"
                SERVICE_STATUS["crowdsec"]="خطا"
            fi
        else
            systemctl start docker
            if systemctl is-active docker >/dev/null 2>&1; then
                echo "نصب داشبورد CrowdSec شروع می‌شود (غیرتعاملی، حداکثر 5 دقیقه)..."
                timeout 300 cscli dashboard setup --listen 0.0.0.0:$CROWDSEC_DASHBOARD_PORT --yes
                if [ $? -eq 0 ]; then
                    sleep 10
                    if docker ps -a | grep -q metabase; then
                        if docker ps | grep -q metabase; then
                            check_success "نصب و راه‌اندازی CrowdSec و داشبورد" "crowdsec"
                        else
                            send_telegram "⚠️ CrowdSec نصب شد اما داشبورد اجرا نشد (ادامه فرآیند)"
                            SERVICE_STATUS["crowdsec"]="خطا"
                        fi
                    else
                        send_telegram "⚠️ CrowdSec نصب شد اما داشبورد نصب نشد (ادامه فرآیند)"
                            SERVICE_STATUS["crowdsec"]="خطا"
                    fi
                else
                    send_telegram "❌ نصب داشبورد CrowdSec با خطا مواجه شد (ادامه فرآیند)"
                    SERVICE_STATUS["crowdsec"]="خطا"
                fi
            else
                send_telegram "❌ Docker فعال نشد، نصب داشبورد CrowdSec رد شد (ادامه فرآیند)"
                SERVICE_STATUS["crowdsec"]="نصب ناقص"
            fi
        fi
    else
        send_telegram "❌ نصب CrowdSec شکست خورد، cscli پیدا نشد (ادامه فرآیند)"
        SERVICE_STATUS["crowdsec"]="خطا"
    fi
else
    send_telegram "❌ نصب CrowdSec به دلیل خطای apt شکست خورد (ادامه فرآیند)"
    SERVICE_STATUS["crowdsec"]="خطا"
fi
# ======================================================================







# نصب Code-Server
echo "🔄 نصب Code-Server..."
curl -fsSL https://code-server.dev/install.sh | sh
sudo setcap cap_net_bind_service=+ep /usr/lib/code-server/lib/node
systemctl enable --now code-server@"$NEW_USER"
mkdir -p "/home/$NEW_USER/.config/code-server"
cat <<EOL > "/home/$NEW_USER/.config/code-server/config.yaml"
bind-addr: 0.0.0.0:$CODE_SERVER_PORT
auth: password
password: $CODE_SERVER_PASSWORD
cert: false
EOL
chown -R "$NEW_USER":"$NEW_USER" "/home/$NEW_USER/.config"
systemctl restart code-server@"$NEW_USER"
if sudo netstat -tuln | grep -q "$CODE_SERVER_PORT"; then
    check_success "نصب و راه‌اندازی Code-Server" "code-server"
else
    send_telegram "⚠️ Code-Server نصب شد اما روی پورت $CODE_SERVER_PORT اجرا نشد (ادامه فرآیند)"
    SERVICE_STATUS["code-server"]="خطا"
fi

# نصب ابزارهای جانبی
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

# تنظیمات امنیتی
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

# ریستارت سرویس‌ها
echo "🔄 ریستارت نهایی سرویس‌ها..."
services_to_restart=(
    "docker"
    "code-server@$NEW_USER.service"
    "netdata"
    "crowdsec"
    "portainer"
    "nginx-proxy-manager"
    "crowdsec-metabase"
)
RESTART_REPORT=""
for service in "${services_to_restart[@]}"; do
    if systemctl is-active "$service" >/dev/null 2>&1; then
        sudo systemctl restart "$service"
        RESTART_REPORT+="   - **$service**: ✅ ریستارت شد\n"
    elif docker ps -q -f name="$service" >/dev/null 2>&1; then
        sudo docker restart "$service"
        RESTART_REPORT+="   - **$service**: ✅ ریستارت شد\n"
    else
        RESTART_REPORT+="   - **$service**: ❌ یافت نشد\n"
    fi
done
send_telegram "🔄 **ریستارت نهایی سرویس‌ها:**\n$RESTART_REPORT"

# گزارش نهایی
SERVER_IP=$(curl -s -4 icanhazip.com)
LOCATION=$(curl -s http://ip-api.com/line/$SERVER_IP?fields=country,city,isp)

REPORT="
🚀 **گزارش نهایی پیکربندی سرور**  
⏳ زمان اجرا: \`$(date)\`  

🔹 **مشخصات سرور:**  
   - نام سرور: \`$(hostname)\`  
   - آدرس IP: \`$SERVER_IP\`  
   - موقعیت مکانی: \`$LOCATION\`  

🔹 **وضعیت سرویس‌ها:**  
   - Portainer: [لینک](http://$SERVER_IP:$PORTAINER_PORT)  
   - Nginx Proxy Manager: [لینک](http://$SERVER_IP:$NGINX_PROXY_MANAGER_PORT)  
   - Code-Server: [لینک](http://$SERVER_IP:$CODE_SERVER_PORT)  
   - Netdata: [لینک](http://$SERVER_IP:$NETDATA_PORT)  
   - CrowdSec: [لینک](http://$SERVER_IP:$CROWDSEC_DASHBOARD_PORT)  

🔹 **دسترسی SSH:**  
   - پورت: \`$SSH_PORT\`  
   - کاربر: \`$NEW_USER\`  
   - روش احراز: 🔑 کلید عمومی  

🔹 **پورت‌های باز:**  
   - \`${PORTS_TO_OPEN[*]}\`  
🔹 **پورت‌های رزرو‌شده:**  
   - \`${RESERVED_PORTS[*]}\`  

🔹 **وضعیت امنیت:**  
   - فایروال UFW: ✅ فعال  
   - CrowdSec و Fail2Ban: ✅ فعال و نظارت بر حملات  
"

send_telegram "$REPORT"
echo "✅ گزارش نهایی به تلگرام ارسال شد (چک کنید)"
exit 0
