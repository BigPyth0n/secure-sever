# Server Setup Script

![GitHub](https://img.shields.io/github/license/YourUsername/secure-sever) ![GitHub last commit](https://img.shields.io/github/last-commit/BigPyth0n/secure-sever)

این اسکریپت یه ابزار خودکار برای راه‌اندازی یه سرور امن و کاربردی روی اوبونتو 22.04 هست. هدفش نصب و تنظیم سرویس‌ها و برنامه‌های ضروری برای مدیریت سرور، مانیتورینگ، و امنیت با کمترین دخالت کاربره.

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
| **Netdata**         | مانیتورینگ عملکرد سرور          | 9001          | `http://<IP>:9001`             |
| **Nginx Proxy Manager** | مدیریت پروکسی و SSL         | 81            | `http://<IP>:81`              |
| **Portainer**       | رابط گرافیکی مدیریت داکر       | 9000          | `http://<IP>:9000`             |

### برنامه‌ها
- **داکر و داکر کامپوز:** برای مدیریت کانتینرها.
- **ابزارهای خط فرمان:** `wget`, `curl`, `net-tools`, `iperf3`, `htop`, `glances`, `tmux`, `rsync`, `vim`, `nano`, `unzip`, `zip`, `build-essential`, `git`, `lftp`.
- **امنیت و اسکن:** `clamav`, `clamav-daemon`, `rkhunter`, `lynis`, `auditd`, `tcpdump`, `nmap`.

---

## پیش‌نیازها
- **سیستم‌عامل:** اوبونتو 22.04 LTS
- **دسترسی root:** باید با کاربر root یا sudo اجرا بشه.
- **اتصال اینترنت:** برای دانلود پکیج‌ها و اسکریپت‌ها.
- **توکن تلگرام:** یه بات تلگرام با توکن و چت آیدی برای دریافت گزارش.

---







### اجرا با بالاترین سطح دسترسی و پرمیشن در سرور


# نصب و تنظیم افزودن CrowdSec با پیکربندی کامل

```
sudo su - root -c "wget https://raw.githubusercontent.com/BigPyth0n/secure-sever/refs/heads/main/ServerConfig-SecurityConfig.sh -O /tmp/ServerConfig-SecurityConfig.sh && chmod +x /tmp/ServerConfig-SecurityConfig.sh && /tmp/ServerConfig-SecurityConfig.sh"
```
|---------------------|----------------------------------|---------------|----------------------------------|

# نحوه اجرا و فعال سازی اسکریپت ارسال گزارش به تلگرام
### ذخیره اسکریپت:

```
sudo wget https://raw.githubusercontent.com/BigPyth0n/secure-sever/main/SecurityReport-toTelegram.sh -O /usr/local/bin/SecurityReport-toTelegram.sh
sudo chmod +x /usr/local/bin/SecurityReport-toTelegram.sh
```

### تنظیم استفاده از کرون (Cron Job):

```
(sudo crontab -l 2>/dev/null; echo "0 */6 * * * /usr/local/bin/SecurityReport-toTelegram.sh") | sudo crontab -
```
### بررسی کرون جاب:


```
sudo crontab -l
```
## اجرای سریع و دستی برای تست
```
sudo /usr/local/bin/SecurityReport-toTelegram.sh
```


# اجرای بک آپ گیری و چک و ارسال پوشه KitZone3 به گوگل درایو
```
sudo wget https://raw.githubusercontent.com/BigPyth0n/secure-sever/refs/heads/main/backup_kitzone3.sh -O /usr/local/bin/backup_kitzone3.sh && sudo chmod +x /usr/local/bin/backup_kitzone3.sh && /usr/local/bin/backup_kitzone3.sh
```



# اضافه کردن کرون به لیست کرون های کاربر رووت
```
(sudo crontab -l 2>/dev/null; echo "0 0 * * * /home/bigpython/backup_kitzone3.sh") | sudo crontab -
```


## نکات
#### پیش‌نیاز: مطمئن شو rclone نصب و تنظیم شده باشه (با rclone config).
# برای تمدید توکن فقط کافی هست این دستورات رو بزنیم تا در سرور مجازی بدون مرورگر لینک بهمون بده
```
bigpython@KitZone-Server:~$ rclone config reconnect gdrive:
Already have a token - refresh?
y) Yes (default)
n) No
y/n> n
```
#### فضا: اسکریپت چک می‌کنه که حداقل ۲ گیگابایت فضای خالی باشه.
#### خروجی: فایل لاگ (backup_log_YYYY-MM-DD.txt) همه جزئیات رو نگه می‌داره.

### تنظیم برای کاربر bigpyth0n
#### اجرای دوره‌ای: می‌تونی این اسکریپت رو با cron تنظیم کنی که مثلاً هر روز یا هفته اجرا بشه:


#### اجرا هر روز ساعت 12 بامداد

```
crontab -e
0 0 * * * /home/bigpython/backup_kitzone3.sh
```

#### اجرا هر هفته یک‌شنبه ساعت 3 صبح

```
crontab -e
0 3 * * 0 /home/bigpython/backup_kitzone3.sh
```

#### اجرا هر 10 روز یک بار ساعت 6 صبح


```
crontab -e
0 6 */10 * * /home/bigpython/backup_kitzone3.sh
```
## اگه می‌خوای مطمئن شی اسکریپت درست کار می‌کنه، قبل از اینکه به cron وابسته باشی، خودت اجراش کن:
/home/bigpython/backup_kitzone3.sh


