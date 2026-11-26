# 🖥️ NOC Network Monitoring Utility

Aplikasi utilitas **Network Operations Center (NOC)** berbasis **Python** yang dikemas menjadi file *executable* mandiri (`.exe`) untuk memantau status konektivitas dan kesehatan perangkat jaringan secara *real-time* pada lingkungan operasional maupun jaringan lokal (VLAN).

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows_x64-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Build](https://img.shields.io/badge/Packaged-PyInstaller_(.exe)-0F172A?style=for-the-badge&logo=python&logoColor=38BDF8)
![Status](https://img.shields.io/badge/Status-Production_Ready-10B981?style=for-the-badge)

---

## ✨ Fitur Utama

- **Pemantauan Status Jaringan *Real-Time*:** Memeriksa status *reachability* / latensi host, IP, atau layanan target secara berkala.
- **Indikator Status Visual:** Membedakan kondisi *online*, *degraded* / latensi tinggi, dan *offline* / *unreachable* agar anomali cepat terlihat.
- **Siap Dijalankan Tanpa Instalasi Python:** Dikemas menjadi *standalone* `.exe` sehingga mudah didistribusikan ke workstation operasional.
- **Konfigurasi Fleksibel:** Pengaturan daftar target, *timeout*, dan interval pengecekan dapat disesuaikan tanpa perlu mengubah kode sumber.
- **Log & Riwayat Kejadian:** Mencatat perubahan status atau gangguan untuk mempermudah *troubleshooting* dan pelaporan *shift*.
- **Pembaruan Terkelola:** Mendukung pembaruan versi aplikasi melalui repositori GitHub.

---

## 🏗️ Arsitektur & Alur Kerja

```text
+--------------------+      ICMP / TCP / HTTP      +-----------------------+
|  NOC Utility.exe   | ----------------------------> |  Target Hosts / Nodes |
|  (Python Runtime)  | <---------------------------- |  (Router / Switch /   |
+--------------------+      Response & Latency       |   Server / VLAN IP)   |
         |                                           +-----------------------+
         v
+--------------------+
| Status & Event Log |
| (UI / Console /    |
|  Config & Update)  |
+--------------------+
```

---

## 📦 Penggunaan (End User `.exe`)

1. Unduh paket rilis terbaru (`.exe`) dari halaman **Releases** repositori ini.
2. Letakkan file `.exe` pada direktori kerja yang diinginkan (misalnya `C:\NOC-Monitor\` atau folder lokal operasional).
3. Siapkan file konfigurasi (jika menggunakan konfigurasi eksternal, misalnya `config.json` atau `.env`) sesuai format yang disediakan.
4. Jalankan file `.exe` (disarankan menjalankan sebagai *Administrator* bila pemeriksaan jaringan memerlukannya).

---

## 🛠️ Pengembangan & Build `.exe` (Developer)

### Prasyarat
- **Python 3.10+**
- **pip** & **virtualenv** (disarankan)
- **PyInstaller**

### 1. Clone Repositori & Siapkan Environment
```bash
git clone [https://github.com/ibrahim742/NOC-NETWORK.git](https://github.com/ibrahim742/NOC-NETWORK.git)
cd NOC-NETWORK
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install pyinstaller
```

### 2. Jalankan dari Source Code
```bash
python main.py
```
*(Sesuaikan `main.py` dengan nama entrypoint utama pada proyekmu.)*

### 3. Build Menjadi File `.exe`
Build single-file executable:
```bash
pyinstaller --noconfirm --onefile --name "NOC-Network-Monitor" main.py
```
*(Jika aplikasi memakai antarmuka GUI tanpa jendela konsol hitam, tambahkan flag `--noconsole` atau `--windowed`.)*

Hasil file `.exe` akan tersedia di folder `dist\NOC-Network-Monitor.exe`.

---

## 📁 Struktur Proyek

```text
NOC-NETWORK/
├── dist/               # Hasil build executable (.exe)
├── build/              # File sementara proses build PyInstaller
├── config/             # Contoh konfigurasi / daftar target host
├── logs/               # Penyimpanan log aktivitas & status jaringan
├── main.py             # Entrypoint utama aplikasi
├── requirements.txt    # Daftar dependensi Python
└── README.md           # Dokumentasi proyek
```

---

## 🔒 Catatan Operasional & Keamanan

- Pastikan aturan *firewall* dan kebijakan jaringan internal mengizinkan lalu lintas pemeriksaan dari host tempat `.exe` dijalankan.
- Hindari menyimpan kredensial sensitif atau *token* secara *hardcoded* di dalam kode sumber maupun file konfigurasi publik.
- Lakukan pengujian pada lingkungan *staging* atau jaringan uji sebelum mengganti *binary* `.exe` di *workstation* aktif.

---

Semoga proyek utilitas NOC ini membantu mempercepat pemantauan jaringan dan menjaga keandalan operasional sehari-hari.
