# Sentinel-Trap Honeypot

Bu proje, SSH, HTTP ve diğer açık portları izleyen, saldırı girişimlerini kaydeden bir güvenlik tuzağı (honeypot) örneğidir. Senaryo tabanlı sahte servislerle gerçekçi bir saldırı yüzeyi sunar.

## Özellikler

- SSH honeypot ve sahte shell
- HTTP login sayfası ve kullanıcı/parola yakalama
- Raw TCP / fake servisler: FTP, Telnet, MySQL, Redis
- SQLite ve MongoDB depolama desteği
- Telegram ve SMTP e-posta uyarıları
- IP analizi ve otomatik bloklama
- YAML tabanlı yapılandırma
- JSON ve veritabanı log kaydı

## Çalıştırma

Yerel geliştirme:

```bash
go run ./cmd/honeypot
```

Docker ile canlı yayın:

```bash
docker compose up --build
```

> 21 ve 23 gibi düşük portlar için root/privileged çalışma gerekir. Bu yüzden gerçek canlı yayın için Docker çok daha güvenlidir.

## Yapılandırma

Ayarlar [configs/config.yaml](configs/config.yaml) dosyasında yapılır.

- `services.ssh.enabled`
- `services.http.enabled`
- `services.raw_tcp.enabled`
- `logging.file_path`
- `storage.type`
- `analysis.threshold`
- `notifier.telegram_enabled`
- `notifier.email.enabled`

## Güvenlik notu

Bu proje eğitim ve güvenlik araştırma amaçlıdır. Yalnızca izin verilen ağlarda ve lisanslı ortamda kullanılır.
# HoneyPot
