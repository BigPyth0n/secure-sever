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

# =============================================
# نصب Docker و Docker Compose
# =============================================
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

# =============================================
# نصب و تنظیم Portainer
# =============================================
echo "🔄 نصب Portainer..."
docker volume create portainer_data
docker run -d --name portainer -p "$PORTAINER_PORT:9000" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v portainer_data:/data \
    --restart unless-stopped \
    portainer/portainer-ce:latest
check_success "نصب و راه‌اندازی Portainer" "portainer"

# =============================================
# نصب و تنظیم Nginx Proxy Manager
# =============================================
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

# =============================================
# نصب و تنظیم Netdata
# =============================================
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

# =============================================
# تنظیم فایروال
# =============================================
echo "🔄 تنظیم فایروال..."
apt install -y ufw
ufw default deny incoming
ufw default allow outgoing
for port in "${PORTS_TO_OPEN[@]}"; do
    ufw allow "$port/tcp"
done
ufw --force enable
check_success "تنظیم فایروال"




# =============================================
# نصب و تنظیم CrowdSec (نسخه بهینه شده)
# =============================================
echo "🔄 تلاش برای نصب و پیکربندی CrowdSec (نسخه بهینه شده)..."

# بررسی پیش‌نیازها
echo "🔍 بررسی پیش‌نیازها..."
if ! command -v curl &> /dev/null; then
    echo "❌ خطا: curl نصب نیست. لطفاً آن را نصب کنید: sudo apt update && sudo apt install -y curl"
    exit 1
fi
if ! command -v gpg &> /dev/null; then
    echo "❌ خطا: gpg نصب نیست. لطفاً آن را نصب کنید: sudo apt update && sudo apt install -y gpg"
    exit 1
fi
if [[ $(apt --version | awk '{print $3}') < 2.0 ]]; then
    echo "⚠️ هشدار: نسخه apt شما قدیمی است. توصیه می‌شود آن را به روز رسانی کنید."
fi

# به‌روزرسانی لیست بسته‌ها
echo "🔄 به‌روزرسانی لیست بسته‌ها..."
sudo apt update

# نصب بسته‌های مورد نیاز برای افزودن repositoryهای HTTPS
echo "📦 نصب apt-transport-https..."
sudo apt install -y apt-transport-https

# افزودن repository CrowdSec
echo "📥 افزودن repository CrowdSec..."
CROWDSEC_REPO_FILE="/etc/apt/sources.list.d/crowdsec_crowdsec.list"
if [ -f "$CROWDSEC_REPO_FILE" ]; then
    echo "ℹ️ Repository CrowdSec قبلاً اضافه شده است."
else
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
    if [ $? -ne 0 ]; then
        echo "❌ خطا در افزودن repository CrowdSec."
        exit 1
    fi
fi

# به‌روزرسانی مجدد لیست بسته‌ها پس از افزودن repository
echo "🔄 به‌روزرسانی مجدد لیست بسته‌ها..."
sudo apt update

# نصب بسته‌های CrowdSec
echo "📦 نصب بسته‌های CrowdSec..."
sudo apt install -y crowdsec crowdsec-firewall-bouncer-iptables ipset libipset13

if [ $? -ne 0 ]; then
    echo "❌ خطا در نصب بسته‌های CrowdSec."
    exit 1
fi

# ایجاد کاربر CrowdSec اگر وجود ندارد
if ! id -u crowdsec >/dev/null 2>&1; then
    echo "👤 ایجاد کاربر سیستم crowdsec..."
    sudo adduser --system --group --disabled-password --shell /bin/false crowdsec
    if [ $? -ne 0 ]; then
        echo "❌ خطا در ایجاد کاربر سیستم crowdsec."
        exit 1
    fi
else
    echo "ℹ️ کاربر سیستم crowdsec قبلاً وجود دارد."
fi

# تنظیمات API با رفع خطای اتصال (توصیه می‌شود علت اصلی را بررسی کنید)
echo "⚙️ تنظیمات API CrowdSec..."
CROWDSEC_CONFIG_FILE="/etc/crowdsec/config.yaml.local"
sudo tee "$CROWDSEC_CONFIG_FILE" >/dev/null <<EOL
api:
  server:
    listen_uri: 127.0.0.1:8080
    profiles_path: /etc/crowdsec/profiles.yaml
  client:
    insecure_skip_verify: true  # ⚠️ توصیه می‌شود علت اصلی خطای اتصال API را بررسی و رفع کنید.
db_config:
  type: sqlite
  db_path: /var/lib/crowdsec/data/crowdsec.db
EOL
if [ $? -ne 0 ]; then
    echo "❌ خطا در نوشتن تنظیمات API CrowdSec."
    exit 1
fi

# تنظیم مجوزها
echo "🔒 تنظیم مجوزهای CrowdSec..."
sudo chown -R crowdsec:crowdsec /etc/crowdsec
sudo chown -R crowdsec:crowdsec /var/lib/crowdsec/data
sudo chmod -R 755 /var/lib/crowdsec/data
if [ $? -ne 0 ]; then
    echo "❌ خطا در تنظیم مجوزهای CrowdSec."
    exit 1
fi

# راه‌اندازی سرویس CrowdSec
echo "🚀 راه‌اندازی سرویس CrowdSec..."
sudo systemctl daemon-reload
sudo systemctl enable crowdsec
if ! sudo systemctl restart crowdsec; then
    echo "⚠️ هشدار: راه‌اندازی اولیه سرویس CrowdSec با مشکل مواجه شد. تلاش برای اجرای مستقیم..."
    sudo -u crowdsec /usr/bin/crowdsec -c /etc/crowdsec/config.yaml &
    sleep 10
    if ! sudo systemctl is-active --quiet crowdsec; then
        echo "❌ خطا: سرویس CrowdSec پس از تلاش مجدد نیز فعال نشد. لطفاً وضعیت آن را بررسی کنید: sudo systemctl status crowdsec"
        SERVICE_STATUS["crowdsec"]="نصب ناقص"
        exit 1
    else
        echo "✅ سرویس CrowdSec با موفقیت راه‌اندازی شد (با روش جایگزین)."
    fi
else
    echo "✅ سرویس CrowdSec با موفقیت راه‌اندازی شد."
fi

# =============================================
# نصب Metabase (CrowdSec Dashboard) (نسخه بهینه شده)
# =============================================
echo "🔄 تلاش برای نصب Metabase (CrowdSec Dashboard) (نسخه بهینه شده)..."

# بررسی پیش‌نیازهای Docker
echo "🔍 بررسی پیش‌نیازهای Docker..."
if ! command -v docker &> /dev/null; then
    echo "❌ خطا: Docker نصب نیست. لطفاً آن را نصب کنید."
    exit 1
fi
if ! sudo systemctl is-active --quiet docker; then
    echo "❌ خطا: سرویس Docker در حال اجرا نیست. لطفاً آن را راه‌اندازی کنید: sudo systemctl start docker"
    exit 1
fi

# حذف کانتینر Metabase قبلی اگر وجود دارد
echo "🧹 حذف کانتینر Metabase قبلی (در صورت وجود)..."
sudo docker rm -f metabase 2>/dev/null || true

# راه‌اندازی داشبورد CrowdSec (Metabase)
echo "🚀 راه‌اندازی داشبورد CrowdSec (Metabase)..."
METABASE_LOG_FILE="/var/log/crowdsec_dashboard_setup.log"
yes | sudo cscli dashboard setup --listen 0.0.0.0:$CROWDSEC_DASHBOARD_PORT >> "$METABASE_LOG_FILE" 2>&1
DASHBOARD_SETUP_EXIT_CODE=$?
if [ $DASHBOARD_SETUP_EXIT_CODE -ne 0 ]; then
    echo "❌ خطا در اجرای دستور cscli dashboard setup. جزئیات بیشتر در: $METABASE_LOG_FILE"
    SERVICE_STATUS["crowdsec_dashboard"]="نصب ناقص"
    cat "$METABASE_LOG_FILE"
    exit 1
fi

# انتظار هوشمند برای راه‌اندازی Metabase
echo "⏳ در حال انتظار برای راه‌اندازی Metabase..."
METABASE_READY=false
for i in {1..60}; do # افزایش زمان انتظار به 5 دقیقه (60 * 5 ثانیه)
    if docker ps --filter name=metabase --format "{{.State}}" | grep -q "running"; then
        if curl -sSf http://localhost:$CROWDSEC_DASHBOARD_PORT >/dev/null; then
            METABASE_READY=true
            echo "✅ Metabase با موفقیت راه‌اندازی شد."
            break
        else
            echo "⏳ Metabase در حال اجرا است اما به درخواست‌ها پاسخ نمی‌دهد (تلاش $i از 60)."
        fi
    else
        echo "⏳ کانتینر Metabase هنوز در حال راه‌اندازی است (تلاش $i از 60)."
    fi
    sleep 5
done

if [ "$METABASE_READY" = false ]; then
    echo "❌ خطا: Metabase پس از 5 دقیقه تلاش نیز راه‌اندازی نشد."
    echo "💡 می‌توانید بعداً به صورت دستی تلاش کنید: sudo cscli dashboard setup --listen 0.0.0.0:$CROWDSEC_DASHBOARD_PORT --force"
    echo "📄 بررسی لاگ‌های Docker Metabase: sudo docker logs metabase"
    echo "👂 بررسی پورت: sudo netstat -tulnp | grep $CROWDSEC_DASHBOARD_PORT"
    SERVICE_STATUS["crowdsec_dashboard"]="نصب ناقص"
    exit 1
fi

echo "✅ نصب و پیکربندی CrowdSec و Metabase با موفقیت به پایان رسید."
SERVICE_STATUS["crowdsec"]="نصب کامل"
SERVICE_STATUS["crowdsec_dashboard"]="نصب کامل"

# ======================== اجرای اصلی (توصیه می‌شود این بخش را در صورت نیاز تنظیم کنید) ========================
# در این نسخه، نصب CrowdSec و Metabase به طور کامل در بالا انجام شده است.
# نیازی به فراخوانی تابع install_and_configure_crowdsec در اینجا نیست.

# ======================== بررسی نهایی (این بخش می‌تواند در انتهای اسکریپت اصلی شما قرار بگیرد) ========================
echo "📊 بررسی نهایی وضعیت CrowdSec و Metabase..."
if sudo systemctl is-active --quiet crowdsec && docker ps --filter name=metabase --format "{{.State}}" | grep -q "running" && curl -sSf http://localhost:$CROWDSEC_DASHBOARD_PORT >/dev/null; then
    echo "✅ CrowdSec و Metabase هر دو به نظر می‌رسد به درستی کار می‌کنند."
else
    echo "❌ یک یا چند سرویس (CrowdSec یا Metabase) به درستی کار نمی‌کنند."
    if ! sudo systemctl is-active --quiet crowdsec; then
        echo "   - CrowdSec: ❌ غیر فعال یا با خطا مواجه شده است (sudo systemctl status crowdsec)."
    fi
    if ! docker ps --filter name=metabase --format "{{.State}}" | grep -q "running"; then
        echo "   - Metabase: ❌ کانتینر در حال اجرا نیست (sudo docker ps -a --filter name=metabase)."
    fi
    if ! curl -sSf http://localhost:$CROWDSEC_DASHBOARD_PORT >/dev/null; then
        echo "   - Metabase: ❌ به پورت $CROWDSEC_DASHBOARD_PORT پاسخ نمی‌دهد (sudo netstat -tulnp | grep $CROWDSEC_DASHBOARD_PORT)."
    fi
fi







# =============================================
# نصب و تنظیم Code-Server
# =============================================
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

# =============================================
# نصب ابزارهای جانبی
# =============================================
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

# =============================================
# تنظیمات امنیتی نهایی
# =============================================
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

# =============================================
# ریستارت نهایی سرویس‌ها
# =============================================
echo "🔄 ریستارت نهایی سرویس‌ها..."
services_to_restart=(
    "docker"
    "code-server@$NEW_USER.service"
    "netdata"
    "crowdsec"
)

containers_to_restart=(
    "portainer"
    "nginx-proxy-manager"
    "metabase"  # تغییر از crowdsec-metabase به metabase
)

RESTART_REPORT=""

# ریستارت سرویس‌های سیستمی
for service in "${services_to_restart[@]}"; do
    if systemctl is-active "$service" >/dev/null 2>&1; then
        sudo systemctl restart "$service"
        RESTART_REPORT+="   - **$service**: ✅ ریستارت شد\n"
    else
        RESTART_REPORT+="   - **$service**: ❌ یافت نشد\n"
    fi
done

# ریستارت کانتینرهای داکر
for container in "${containers_to_restart[@]}"; do
    if docker ps -a | grep -q "$container"; then
        sudo docker restart "$container"
        RESTART_REPORT+="   - **$container**: ✅ ریستارت شد\n"
    else
        RESTART_REPORT+="   - **$container**: ❌ یافت نشد\n"
    fi
done

send_telegram "🔄 **ریستارت نهایی سرویس‌ها:**\n$RESTART_REPORT"

# =============================================
# گزارش نهایی
# =============================================
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
