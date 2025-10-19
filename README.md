# 🔐 VaultCrypt

**Professional Encryption Suite for Windows**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++](https://img.shields.io/badge/C++-17-blue.svg)](https://isocpp.org/)
[![Qt](https://img.shields.io/badge/Qt-5.15-green.svg)](https://www.qt.io/)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)

VaultCrypt is a encryption application that delivers protection with a clean and intuitive interface.
Built with **C++17**, **Qt5**, and **trusted cryptographic libraries**.

---

## ✨ Key Features

### **Encryption Standards**

* AES-256-GCM — NSA Suite B compliant
* XChaCha20-Poly1305 — fast and secure
* Authenticated encryption to prevent data tampering

### **Key Derivation**

* Argon2id — PHC winner, memory-hard and secure
* PBKDF2-SHA256 — compatible with legacy systems
* Configurable parameters for strength and performance

### **Modern GUI**

* Clean, minimalist Qt5 interface
* Three themes: Light, Dark, Midnight
* Adjustable accent colors
* Scales correctly on all resolutions

### **Security Utilities**

* Secure file wiping (3-pass overwrite)
* Batch file encryption/decryption
* Key management with random key generation
* Built-in password and key generator

### **Cross-Platform Ready**

* Native on Windows
* Portable build supports Linux/macOS
* CLI version included for automation

---

## 🚀 Quick Start

### **Download**


**Portable Build**
[VaultCrypt-1.0.0-Portable.zip](https://github.com/Kryptos-s/VaultCrypt/releases/tag/release)

### **Usage**

**Encrypt**

```
Select Input File → Enter Password → ENCRYPT
```

**Decrypt**

```
Select Encrypted File → Enter Password → DECRYPT
```

**Generate Key**

```
Key Manager → Generate New Key → Save Securely
```

---

## 📦 Installation

### **Windows**

**Installer**

```powershell
VaultCrypt-Setup.exe
```

**Portable**

```powershell
Expand-Archive VaultCrypt-Portable.zip
.\VaultCrypt\vaultcrypt-gui.exe
```

---

## 🧩 Build from Source

See [BUILDING.md](BUILDING.md) for detailed instructions.

**Quick build:**

```bash
# Requirements: CMake 3.20+, vcpkg, Qt5, Crypto++, libsodium
git clone https://github.com/yourusername/VaultCrypt.git
cd VaultCrypt
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=[vcpkg-root]/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```



---

## 🛡️ Security

VaultCrypt uses **peer-reviewed** and **industry-standard** libraries:

* **Crypto++** — AES-256-GCM, SHA-2
* **libsodium** — XChaCha20-Poly1305, Argon2id

No proprietary encryption.
No telemetry.
No hidden data collection.

**Security Audit:** Pending. Use at your discretion.
**Report Vulnerabilities:** `security@vaultcrypt.example`
See [SECURITY.md](SECURITY.md) for full policy.

---

## 🤝 Contributing

Contributions are welcome. Please review:

* [CONTRIBUTING.md](CONTRIBUTING.md)


**Quick workflow:**

```bash
git checkout -b feature/new-feature
git commit -m "Add new feature"
git push origin feature/new-feature
```

---

## 🗺️ Roadmap

* [x] AES-256-GCM
* [x] XChaCha20-Poly1305
* [x] Qt5 GUI
* [x] Theme system
* [ ] HSM (Hardware Security Module) support
* [ ] Cloud integration
* [ ] Mobile clients
* [ ] Pre-encryption compression
* [ ] Steganography module
* [ ] Multi-language UI

---

## 🐞 Known Issues

See [GitHub Issues](https://github.com/Kryptos-s/VaultCrypt/issues).

---

## 📜 License

Licensed under the **MIT License**.
See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

* [Crypto++](https://www.cryptopp.com/)
* [libsodium](https://libsodium.org/)
* [Qt Framework](https://www.qt.io/)
* [vcpkg](https://github.com/microsoft/vcpkg)

---

## 📞 Contact

**Issues:** [GitHub Issues](https://github.com/Kryptos-s/VaultCrypt/issues)
**Discussions:** [GitHub Discussions](https://github.com/Kryptos-s/VaultCrypt/discussions)


---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Kryptos-s/VaultCrypt\&type=Date)](https://star-history.com/#yourusername/VaultCrypt&Date)

---

**© 2025 VaultCrypt Contributors**
Secure. Transparent. Open Source.
