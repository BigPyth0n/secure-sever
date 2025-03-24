# Server Setup Script

![GitHub](https://img.shields.io/github/license/YourUsername/secure-sever) ![GitHub last commit](https://img.shields.io/github/last-commit/BigPyth0n/secure-sever)

این اسکریپت یه ابزار خودکار برای راه‌اندازی یه سرور امن و کاربردی روی اوبونتو 20.04 هست. هدفش نصب و تنظیم سرویس‌ها و برنامه‌های ضروری برای مدیریت سرور، مانیتورینگ، و امنیت با کمترین دخالت کاربره.

---

## ویژگی‌ها
- **نصب خودکار سرویس‌ها:** داکر، Portainer، Code-Server، CrowdSec، Netdata، و Nginx Proxy Manager رو نصب می‌کنه.
- **امنیت:** پورت SSH رو تغییر می‌ده، ورود با رمز رو غیرفعال می‌کنه، و کلید عمومی رو تنظیم می‌کنه.
- **فایروال:** UFW رو با پورت‌های مشخص تنظیم می‌کنه.
- **مانیتورینگ:** Netdata برای مشاهده عملکرد سرور و CrowdSec برای محافظت در برابر حملات.
- **گزارش:** یه گزارش جامع توی تلگرام با فرمت JSON مانند می‌فرسته.

---

## سرویس‌ها و برنامه‌های نصب‌شده
### سرویس‌ها
| نام                | توضیحات                          | پورت پیش‌فرض | آدرس دسترسی مثال                |
|---------------------|----------------------------------|---------------|----------------------------------|
| **Code-Server**     | محیط توسعه وب (VS Code)         | 1010          | `http://<IP>:1010`             |
| **CrowdSec Dashboard** | داشبورد امنیتی برای CrowdSec   | 3000          | `http://<IP>:3000`             |
| **Netdata**         | مانیتورینگ عملکرد سرور          | 9001          | `http://<IP>:9001`             |
| **Nginx Proxy Manager** | مدیریت پروکسی و SSL         | 81            | `http://<IP>:81`              |
| **Portainer**       | رابط گرافیکی مدیریت داکر       | 9000          | `http://<IP>:9000`             |

### برنامه‌ها
- **داکر و داکر کامپوز:** برای مدیریت کانتینرها.
- **ابزارهای خط فرمان:** `wget`, `curl`, `net-tools`, `iperf3`, `htop`, `glances`, `tmux`, `rsync`, `vim`, `nano`, `unzip`, `zip`, `build-essential`, `git`, `lftp`.
- **امنیت و اسکن:** `clamav`, `clamav-daemon`, `rkhunter`, `lynis`, `auditd`, `tcpdump`, `nmap`.

---

## پیش‌نیازها
- **سیستم‌عامل:** اوبونتو 20.04 LTS
- **دسترسی root:** باید با کاربر root یا sudo اجرا بشه.
- **اتصال اینترنت:** برای دانلود پکیج‌ها و اسکریپت‌ها.
- **توکن تلگرام:** یه بات تلگرام با توکن و چت آیدی برای دریافت گزارش.

---

## نصب و اجرا
### روش 1: مستقیم از GitHub
توی سرور، دستور زیر رو بزن:
   ```
   curl -s https://raw.githubusercontent.com/BigPyth0n/secure-sever/refs/heads/main/secure_setup.sh | sudo bash
```

### روش 2: به صورت دانلود روی سرور و اجرا کردن
 دانلود روی سرور اعطای مجوز و نصب دستی

```
wget https://github.com/BigPyth0n/secure-sever/blob/main/secure_setup.sh
```
```
wget https://raw.githubusercontent.com/BigPyth0n/secure-sever/refs/heads/main/secure_setup.sh
```

### دادن مجوز اجرایی
```
chmod +x secure_setup.sh
```
### و اجرای اسکریپت
```
sudo ./secure_setup.sh
```

   



