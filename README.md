# Secure File Transfer — Phase 2
**Đề tài:** Ứng dụng Truyền tải Tập tin An toàn sử dụng Hệ mật mã lai và Chữ ký số  
**Sinh viên:** Trương Nhật Huy — MSSV 22127168  
**GVHD:** Ngô Đình Hy, Nguyễn Đình Thúc

---

## 📁 Cấu trúc dự án

```
secure_transfer/
│
├── backend/                    ← Python FastAPI Server
│   ├── main.py                 ← Toàn bộ logic mật mã & API routes
│   └── requirements.txt        ← Dependencies
│
└── frontend/                   ← Giao diện người dùng
    ├── index.html              ← Trang chính (Sender + Receiver)
    └── static/
        ├── css/
        │   └── style.css       ← Toàn bộ styles
        └── js/
            └── app.js          ← Logic giao diện + gọi API
```

---

## ⚙️ Cài đặt & Chạy

### 1. Cài dependencies backend
```bash
cd backend
pip install -r requirements.txt
```

### 2. Chạy server
```bash
uvicorn main:app --reload --port 8000
```

### 3. Mở trình duyệt
```
http://localhost:8000
```
> Frontend được FastAPI serve tự động tại `/`

---

## 🔐 API Endpoints

| Method | Endpoint              | Mô tả                                      |
|--------|-----------------------|--------------------------------------------|
| POST   | `/api/keys/generate`  | Sinh cặp khóa RSA-2048                     |
| POST   | `/api/encrypt`        | Alice: Ký số + Mã hóa + Đóng gói          |
| POST   | `/api/decrypt`        | Bob: Giải mã + Xác thực chữ ký            |
| GET    | `/api/health`         | Health check                               |

---

## 🔒 Tiêu chuẩn mật mã (Phase 2 Spec)

| Module                  | Tiêu chuẩn                        |
|-------------------------|-----------------------------------|
| Ký số & RSA             | RSA-2048, PKCS#1 v1.5             |
| Mã hóa Session Key      | RSA-OAEP                          |
| Mã hóa dữ liệu          | AES-256-CBC + PKCS#7 padding      |
| Băm (Hash)              | SHA-256                           |
| Định dạng khóa          | PEM (.pem)                        |

---

## 📦 Package Format (Binary)

```
┌──────────────────────────────────────────┐
│ MAGIC "SFTPKG02" (8 bytes)               │
│ VERSION (1 byte)                         │
│ orig_filename_len (4B) | orig_filename   │
│ sig_len (4B)           | signature       │
│ enc_sk_len (4B)        | encrypted_key   │
│ IV (16 bytes)                            │
│ enc_data_len (4B)      | encrypted_data  │
└──────────────────────────────────────────┘
```

---

## 🔁 Luồng hoạt động

### Alice (Sender)
1. Chọn file gốc + Private Key Sender + Public Key Receiver  
2. Backend tính SHA-256 → Ký bằng RSA (PrivKey Sender)  
3. Sinh Session Key AES-256 → Mã hóa file (AES-CBC)  
4. Mã hóa Session Key bằng RSA-OAEP (PubKey Receiver)  
5. Đóng gói → Trả về `.pkg` để tải xuống  

### Bob (Receiver)
1. Upload file `.pkg` + Private Key Receiver + Public Key Sender  
2. Backend tách lớp gói  
3. Giải mã Session Key (RSA-OAEP + PrivKey Receiver)  
4. Giải mã dữ liệu (AES-256-CBC)  
5. Xác thực chữ ký: SHA-256 lại → So sánh với signature  
6. Trả về kết quả + file gốc để tải xuống  
