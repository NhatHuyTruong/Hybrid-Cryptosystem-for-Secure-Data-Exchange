
**Đề tài:** Ứng dụng Truyền tải Tập tin An toàn sử dụng Hệ mật mã lai và Chữ ký số  
**Sinh viên:** Trương Nhật Huy — MSSV 22127168  
**GVHD:** Ngô Đình Hy, Nguyễn Đình Thúc

---

## 📁 Cấu trúc dự án

```
secure_transfer/
│
├── backend/
│   ├── main.py                 ← FastAPI server (AES encrypt/decrypt, đóng gói)
│   └── requirements.txt
│
└── frontend/
    ├── index.html              ← UI chính (Alice + Bob)
    └── static/
        ├── css/style.css
        └── js/app.js           ← RSA crypto tại browser (forge.js)
```

---

## ⚙️ Cài đặt & Chạy

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Mở trình duyệt: `http://localhost:8000`

---

## 🔐 Kiến trúc bảo mật (RNF-03 Compliant)

> **Private Key KHÔNG BAO GIỜ rời khỏi máy người dùng.**

| Thao tác | Thực hiện tại | Thư viện |
|----------|--------------|---------|
| SHA-256 hash file | Browser | Web Crypto API |
| RSA PKCS#1 v1.5 ký số (Alice) | Browser | forge.js |
| Sinh Session Key | Browser | `crypto.getRandomValues()` |
| RSA-OAEP mã hóa Session Key | Browser | forge.js |
| AES-256-CBC mã hóa file | **Server** | pycryptodome |
| Đóng gói binary | **Server** | Python |
| Tách gói | **Server** | Python |
| RSA-OAEP giải mã Session Key (Bob) | Browser | forge.js |
| AES-256-CBC giải mã file | **Server** | pycryptodome |
| RSA xác thực chữ ký (Bob) | Browser | forge.js |

---

## 🔒 Tiêu chuẩn mật mã

| Module | Tiêu chuẩn |
|--------|-----------|
| Ký số | RSA-2048, PKCS#1 v1.5 |
| Mã hóa Session Key | RSA-OAEP (SHA-256) |
| Mã hóa dữ liệu | AES-256-CBC + PKCS#7 |
| Hàm băm | SHA-256 |
| Định dạng khóa | PEM |

---

## 🔁 Luồng hoạt động

### Alice (Sender)
```
[BROWSER]
  1. Đọc file → SHA-256 → file_hash
  2. RSA_Sign(file_hash, alice_private_key) → signature   ← private key chỉ ở browser
  3. random session_key (32 bytes)
  4. RSA_OAEP_Encrypt(session_key, bob_public_key) → encrypted_sk

[SERVER /api/encrypt-v2]
  5. AES-256-CBC(file, session_key, random_iv) → encrypted_data
  6. Package(signature + encrypted_sk + iv + encrypted_data) → .pkg
```

### Bob (Receiver)
```
[SERVER /api/unpack]
  1. Tách .pkg → { signature, encrypted_sk, iv, encrypted_data }

[BROWSER]
  2. RSA_OAEP_Decrypt(encrypted_sk, bob_private_key) → session_key  ← private key chỉ ở browser
  3. RSA_Verify(signature, alice_public_key) → integrity_ok
  4. Extract hash từ signature → signature_hash

[SERVER /api/decrypt-data]
  5. AES-256-CBC_Decrypt(encrypted_data, session_key, iv) → file_goc

[BROWSER — RF-13]
  6. SHA-256(file_goc) → computed_hash
  7. So sánh computed_hash vs signature_hash → hiển thị kết quả
```

---

## 📦 Package Format (Binary v2)

```
┌──────────────────────────────────────────┐
│ MAGIC "SFTPKG02" (8 bytes)               │
│ VERSION (1 byte) = 0x02                  │
│ orig_filename_len (4B) | orig_filename   │
│ file_hash_hex_len (4B) | file_hash_hex   │
│ sig_len (4B)           | signature       │
│ enc_sk_len (4B)        | encrypted_key   │
│ IV (16 bytes)                            │
│ enc_data_len (4B)      | encrypted_data  │
└──────────────────────────────────────────┘
```

---

## 🔗 API Endpoints

| Method | Endpoint | Mô tả | Private Key? |
|--------|----------|-------|-------------|
| POST | `/api/keys/generate` | Sinh RSA-2048 keypair | Không lưu |
| POST | `/api/encrypt-v2` | AES encrypt + đóng gói | ❌ Không nhận |
| POST | `/api/unpack` | Tách gói .pkg | ❌ Không nhận |
| POST | `/api/decrypt-data` | AES decrypt | ❌ Không nhận |
| GET | `/api/health` | Health check | — |
