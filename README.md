# 🖥️ NOC Network Monitoring

Aplikasi utilitas **Network Operations Center (NOC)** berbasis **Python** yang dikemas menjadi file *executable* mandiri (`.exe`) untuk memantau konektivitas jaringan secara *real-time* pada lingkungan operasional dan jaringan lokal (VLAN).

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows_x64-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Packaged](https://img.shields.io/badge/Build-PyInstaller_(.exe)-0F172A?style=for-the-badge&logo=python&logoColor=38BDF8)
![Repository](https://img.shields.io/badge/GitHub-ibrahim742/NOC--NETWORK-181717?style=for-the-badge&logo=github&logoColor=white)

---

## ✨ Fitur Utama

- **Pemantauan Konektivitas *Real-Time*:** Memeriksa status host dan perangkat jaringan di daftar host serta *subnet* secara berkelanjutan.
- **Manual Ping:** Melakukan pengujian *ping* manual langsung ke IP atau *host* tertentu saat melakukan *troubleshooting* cepat.
- **Deteksi & Alert RTO (*Request Time Out*):** Menandai dan memberi peringatan ketika *host* mengalami *Request Time Out* atau kehilangan respons.
- **Konfigurasi Host & *Subnet*:** Pengelolaan target *host* dan *subnet* yang dipantau agar mudah disesuaikan dengan topologi jaringan lokal.
- **Standalone Windows `.exe`:** Dapat dijalankan di *workstation* operasional tanpa perlu menginstal Python terlebih dahulu.
- **Pembaruan via GitHub:** Mendukung pengecekan/pembaruan versi aplikasi dari repositori GitHub.

---

## 🏗️ Alur Kerja Pemantauan

```text
+-----------------------------------+
|      NOC Network Monitor (.exe)   |
|      (noc-monitoring-network)     |
+-----------------------------------+
        |                       ^
        | Ping / Cek Status     | Status & RTO Alert
        v                       |
+-----------------------------------+
|    Daftar Host & Subnet (VLAN)    |
+-----------------------------------+
        |
        +---> Manual Ping (On-Demand Troubleshooting)
        +---> GitHub Update Check (Pembaruan Rilis)
```

---

## 📦 Penggunaan (`.exe`)

1. Unduh atau salin file `.exe` hasil *build* ke folder kerja di *workstation* (misalnya pada jaringan lokal / VLAN).
2. Pastikan konfigurasi daftar *host* dan *subnet* sudah sesuai dengan segmen jaringan yang dipantau.
3. Jalankan file `.exe` untuk memulai pemantauan konektivitas *real-time* maupun menjalankan *manual ping* saat diperlukan.
4. Pantau indikator status dan *alert* **RTO** apabila ada perangkat atau *link* yang tidak merespons.

---

## 🛠️ Pengembangan & Build `.exe`

### 1. Clone Repositori
```bash
git clone [https://github.com/ibrahim742/NOC-NETWORK.git](https://github.com/ibrahim742/NOC-NETWORK.git)
cd NOC-NETWORK
```

### 2. Siapkan Environment & Jalankan Script
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install pyinstaller
python noc-monitoring-network.py
```

### 3. Build Menjadi File `.exe`
```bash
pyinstaller --noconfirm --onefile --name "NOC-Network-Monitor" noc-monitoring-network.py
```
*(Tambahkan `--noconsole` bila antarmuka aplikasi berjalan dalam mode GUI tanpa jendela terminal terpisah.)*

File *executable* hasil kompilasi akan berada di folder `dist\NOC-Network-Monitor.exe`.

---

## 📁 Struktur Proyek

```text
NOC-NETWORK/
├── dist/                        # Hasil build executable (.exe)
├── build/                       # File sementara proses PyInstaller
├── noc-monitoring-network.py    # Script utama aplikasi monitoring jaringan
├── requirements.txt             # Dependensi Python
└── README.md                    # Dokumentasi proyek
```

---

## 🔒 Catatan Operasional

- Pastikan izin *firewall* dan akses jaringan pada VLAN/subnet tujuan terbuka untuk paket *ping*/pemeriksaan.
- Uji terlebih dahulu rilis `.exe` baru sebelum mengganti *binary* yang sedang dipakai di meja operasional.
- Gunakan *manual ping* untuk memastikan apakah gangguan bersifat *Request Time Out* sesaat, masalah *routing*/*subnet*, atau *down* pada perangkat tujuan.

---

Semoga proyek utilitas NOC ini membantu mempercepat pemantauan jaringan dan menjaga keandalan operasional sehari-hari.
