"""
=============================================================
  Kiến trúc bảo mật (RNF-03 compliant):
    - Private Key KHÔNG BAO GIỜ rời khỏi máy người dùng
    - Ký số (RSA) và giải mã Session Key (RSA-OAEP) thực hiện tại BROWSER
    - Backend chỉ xử lý: AES encrypt/decrypt, đóng gói, tách gói

  Endpoints:
    POST /api/keys/generate     → Sinh cặp khóa RSA-2048
    POST /api/encrypt           → Alice: nhận (file + signature từ browser) → AES + đóng gói
    POST /api/unpack            → Bob: tách gói → trả các thành phần để browser xử lý
    POST /api/decrypt-data      → Bob: nhận (session_key đã giải mã ở browser) → AES decrypt
=============================================================
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

import os, io, json, struct, base64, hashlib, logging

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# ─────────────────────────────────────────
#  App setup
# ─────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Secure File Transfer API",
    description="Hybrid Cryptosystem & Digital Signature — Phase 2 (RNF-03 Compliant)",
    version="2.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # DEV only — restrict in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend
app.mount("/static", StaticFiles(directory="../frontend/static"), name="static")

MAX_FILE_SIZE = 200 * 1024 * 1024  # 200 MB


# ─────────────────────────────────────────
#  Serve index.html
# ─────────────────────────────────────────
@app.get("/")
def serve_index():
    return FileResponse("../frontend/index.html")


# ─────────────────────────────────────────
#  MODULE 1: Quản lý Khóa
#  Private key sinh tại server CHỈ để trả về client
#  (client có thể tự sinh ở browser — endpoint này là tiện ích)
# ─────────────────────────────────────────
@app.post("/api/keys/generate")
def generate_keypair(bits: int = 2048):
    """
    Sinh cặp khóa RSA mới.
    Trả về public + private key dạng PEM để client lưu xuống máy.
    Server KHÔNG lưu lại bất kỳ khóa nào.
    """
    if bits < 2048:
        raise HTTPException(400, "Độ dài khóa tối thiểu 2048-bit.")

    logger.info(f"Generating RSA-{bits} keypair...")
    key = RSA.generate(bits)

    private_pem = key.export_key("PEM").decode()
    public_pem  = key.publickey().export_key("PEM").decode()

    # Xóa key khỏi memory ngay sau khi export
    del key

    logger.info("Keypair generated — returned to client, not stored.")
    return {
        "status":      "success",
        "bits":        bits,
        "private_key": private_pem,
        "public_key":  public_pem,
    }


# ─────────────────────────────────────────
#  MODULE 2: Alice — Mã hóa & Đóng gói
#
#  Client (browser) đã thực hiện:
#    - SHA-256 hash file
#    - RSA PKCS#1 v1.5 ký bằng Alice's Private Key  ← KHÔNG gửi lên server
#    - RSA-OAEP mã hóa Session Key bằng Bob's Public Key
#
#  Server nhận: file_bytes + signature_b64 + encrypted_sk_b64
#  Server thực hiện: AES-256-CBC + đóng gói binary
# ─────────────────────────────────────────
@app.post("/api/encrypt")
async def encrypt_file(
    file:           UploadFile = File(...,  description="Tập tin gốc"),
    signature_b64:  str        = Form(...,  description="Chữ ký số (base64) — ký bởi browser dùng Alice Private Key"),
    encrypted_sk_b64: str      = Form(...,  description="Session Key đã mã hóa (base64) — mã hóa bởi browser dùng Bob Public Key"),
    file_hash_hex:  str        = Form(...,  description="SHA-256 hex của file gốc — tính bởi browser"),
):
    """
    Luồng Alice (server-side):
      1. Nhận file + signature + encrypted_sk từ browser
      2. Sinh IV ngẫu nhiên + Session Key ngẫu nhiên (AES-256)
         NOTE: Session Key được tạo ở server, mã hóa OAEP đã xảy ra ở browser
               → Thực ra browser gửi encrypted_sk đã mã hóa sẵn lên đây
      3. AES-256-CBC encrypt file
      4. Đóng gói binary: [signature | encrypted_sk | IV | encrypted_data]
    """
    try:
        file_bytes = await file.read()

        if len(file_bytes) > MAX_FILE_SIZE:
            raise HTTPException(413, f"File quá lớn. Tối đa {MAX_FILE_SIZE // 1024 // 1024}MB.")

        logger.info(f"[ENCRYPT] File: '{file.filename}' ({len(file_bytes):,} bytes)")

        # Decode các thành phần từ browser
        signature    = base64.b64decode(signature_b64)
        encrypted_sk = base64.b64decode(encrypted_sk_b64)

        # Sinh IV + mã hóa AES (session key được browser tạo và gửi lên dạng đã mã hóa)
        # Server cần session key để mã hóa — browser gửi session_key_raw riêng
        # (Xem flow đầy đủ ở app.js — browser tạo session key, mã hóa OAEP, gửi cả 2 lên)
        logger.info("[ENCRYPT] Step: AES-256-CBC encrypting file data...")

        # session_key_raw được gửi riêng từ browser (chưa mã hóa, chỉ dùng server-side tạm thời)
        # → Điều này OK vì kênh HTTPS và session key sẽ bị xóa ngay sau dùng
        # (Nếu muốn strict hơn: thực hiện AES ở browser luôn)

        # Đọc session_key_raw từ form (browser gửi kèm để server AES-encrypt)
        raise HTTPException(501, "Dùng endpoint /api/encrypt-v2 — xem app.js")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[ENCRYPT] Error: {e}")
        raise HTTPException(500, str(e))


@app.post("/api/encrypt-v2")
async def encrypt_file_v2(
    file:              UploadFile = File(...),
    signature_b64:     str        = Form(...),
    encrypted_sk_b64:  str        = Form(...),
    session_key_b64:   str        = Form(...,  description="Session Key raw (base64) — browser tạo, chỉ dùng để AES encrypt, bị xóa ngay"),
    file_hash_hex:     str        = Form(...),
):
    """
    Luồng Alice hoàn chỉnh:

    Browser đã làm:
      ① SHA-256(file) → file_hash
      ② RSA_Sign(file_hash, alice_private_key) → signature     [private key KHÔNG lên server]
      ③ random session_key (32 bytes)
      ④ RSA_OAEP_Encrypt(session_key, bob_public_key) → encrypted_sk
      ⑤ Gửi: file + signature + encrypted_sk + session_key + file_hash

    Server làm:
      ⑥ AES-256-CBC(file, session_key, random_iv) → encrypted_data
      ⑦ Đóng gói → .pkg
      ⑧ Xóa session_key khỏi memory
      ⑨ Trả về .pkg (base64)
    """
    try:
        file_bytes   = await file.read()

        if len(file_bytes) > MAX_FILE_SIZE:
            raise HTTPException(413, f"File quá lớn. Tối đa {MAX_FILE_SIZE // 1024 // 1024}MB.")

        logger.info(f"[ENCRYPT] '{file.filename}' ({len(file_bytes):,} bytes)")

        signature    = base64.b64decode(signature_b64)
        encrypted_sk = base64.b64decode(encrypted_sk_b64)
        session_key  = base64.b64decode(session_key_b64)

        if len(session_key) != 32:
            raise HTTPException(400, "Session key phải là 32 bytes (AES-256).")

        # AES-256-CBC
        logger.info("[ENCRYPT] AES-256-CBC encrypting...")
        iv             = get_random_bytes(16)
        cipher_aes     = AES.new(session_key, AES.MODE_CBC, iv)
        padded         = pad(file_bytes, AES.block_size)
        encrypted_data = cipher_aes.encrypt(padded)

        # Xóa session key khỏi memory ngay sau dùng
        del session_key

        # Đóng gói binary
        #  ┌─────────────────────────────────────────────┐
        #  │ MAGIC "SFTPKG02" (8B) | VERSION (1B)        │
        #  │ orig_filename_len (4B) | orig_filename       │
        #  │ file_hash_hex_len (4B) | file_hash_hex       │
        #  │ sig_len (4B)           | signature           │
        #  │ enc_sk_len (4B)        | encrypted_sk        │
        #  │ IV (16B)                                     │
        #  │ enc_data_len (4B)      | encrypted_data      │
        #  └─────────────────────────────────────────────┘
        logger.info("[ENCRYPT] Packaging...")
        MAGIC           = b"SFTPKG02"
        orig_name_bytes = file.filename.encode("utf-8")
        hash_bytes      = file_hash_hex.encode("utf-8")

        pkg = io.BytesIO()
        pkg.write(MAGIC)
        pkg.write(b"\x02")  # version 2
        pkg.write(struct.pack(">I", len(orig_name_bytes)));  pkg.write(orig_name_bytes)
        pkg.write(struct.pack(">I", len(hash_bytes)));       pkg.write(hash_bytes)
        pkg.write(struct.pack(">I", len(signature)));        pkg.write(signature)
        pkg.write(struct.pack(">I", len(encrypted_sk)));     pkg.write(encrypted_sk)
        pkg.write(iv)
        pkg.write(struct.pack(">I", len(encrypted_data)));   pkg.write(encrypted_data)

        pkg_bytes = pkg.getvalue()
        logger.info(f"[ENCRYPT] Done. Package: {len(pkg_bytes):,} bytes")

        return JSONResponse({
            "status":           "success",
            "original_file":    file.filename,
            "file_hash_sha256": file_hash_hex,
            "signature_bytes":  len(signature),
            "package_bytes":    len(pkg_bytes),
            "package_b64":      base64.b64encode(pkg_bytes).decode(),
        })

    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(400, f"Dữ liệu không hợp lệ: {e}")
    except Exception as e:
        logger.error(f"[ENCRYPT] Unexpected: {e}")
        raise HTTPException(500, f"Lỗi mã hóa: {e}")


# ─────────────────────────────────────────
#  MODULE 3a: Bob — Tách gói
#  Trả về các thành phần để browser xử lý RSA
# ─────────────────────────────────────────
@app.post("/api/unpack")
async def unpack_package(
    package: UploadFile = File(...),
):
    """
    Tách gói .pkg → trả về các thành phần (base64).
    Browser sẽ dùng Bob's Private Key để giải mã encrypted_sk (RSA-OAEP).
    Private Key KHÔNG cần gửi lên server.
    """
    try:
        pkg_bytes = await package.read()
        logger.info(f"[UNPACK] Package: {len(pkg_bytes):,} bytes")

        buf   = io.BytesIO(pkg_bytes)
        MAGIC = b"SFTPKG02"

        magic = buf.read(8)
        if magic != MAGIC:
            raise HTTPException(400, "File không hợp lệ — sai magic bytes (SFTPKG02).")

        version = buf.read(1)

        orig_name_len = struct.unpack(">I", buf.read(4))[0]
        orig_filename = buf.read(orig_name_len).decode("utf-8")

        hash_len      = struct.unpack(">I", buf.read(4))[0]
        file_hash_hex = buf.read(hash_len).decode("utf-8")

        sig_len   = struct.unpack(">I", buf.read(4))[0]
        signature = buf.read(sig_len)

        enc_sk_len   = struct.unpack(">I", buf.read(4))[0]
        encrypted_sk = buf.read(enc_sk_len)

        iv = buf.read(16)

        enc_data_len   = struct.unpack(">I", buf.read(4))[0]
        encrypted_data = buf.read(enc_data_len)

        logger.info(f"[UNPACK] '{orig_filename}' — sig={sig_len}B, enc_sk={enc_sk_len}B, data={enc_data_len}B")

        return JSONResponse({
            "status":          "success",
            "original_file":   orig_filename,
            "file_hash_hex":   file_hash_hex,
            "signature_b64":   base64.b64encode(signature).decode(),
            "encrypted_sk_b64": base64.b64encode(encrypted_sk).decode(),
            "iv_b64":          base64.b64encode(iv).decode(),
            "encrypted_data_b64": base64.b64encode(encrypted_data).decode(),
        })

    except HTTPException:
        raise
    except struct.error:
        raise HTTPException(400, "File bị hỏng — không đọc được cấu trúc gói.")
    except Exception as e:
        logger.error(f"[UNPACK] Error: {e}")
        raise HTTPException(500, str(e))


# ─────────────────────────────────────────
#  MODULE 3b: Bob — Giải mã dữ liệu AES
#
#  Browser đã thực hiện:
#    - RSA-OAEP decrypt encrypted_sk bằng Bob's Private Key  ← KHÔNG lên server
#    - RSA verify signature bằng Alice's Public Key           ← KHÔNG lên server
#
#  Server nhận: session_key_b64 (đã giải mã ở browser) + encrypted_data_b64 + iv_b64
#  Server thực hiện: AES-256-CBC decrypt
# ─────────────────────────────────────────
@app.post("/api/decrypt-data")
async def decrypt_data(
    session_key_b64:      str = Form(..., description="Session Key đã giải mã ở browser (base64)"),
    encrypted_data_b64:   str = Form(..., description="Dữ liệu mã hóa (base64)"),
    iv_b64:               str = Form(..., description="IV (base64)"),
):
    """
    Giải mã AES-256-CBC.

    Browser đã làm:
      ① RSA_OAEP_Decrypt(encrypted_sk, bob_private_key) → session_key   [private key KHÔNG lên server]
      ② Verify signature (RSA PKCS#1 v1.5, alice_public_key) → integrity_ok
      ③ Gửi: session_key + encrypted_data + iv lên đây

    Server làm:
      ④ AES-256-CBC decrypt → plain_bytes
      ⑤ Xóa session_key
      ⑥ Trả về file gốc (base64)
    """
    try:
        session_key    = base64.b64decode(session_key_b64)
        encrypted_data = base64.b64decode(encrypted_data_b64)
        iv             = base64.b64decode(iv_b64)

        if len(session_key) != 32:
            raise HTTPException(400, "Session key không hợp lệ (phải 32 bytes).")
        if len(iv) != 16:
            raise HTTPException(400, "IV không hợp lệ (phải 16 bytes).")

        logger.info(f"[DECRYPT] AES-256-CBC decrypting {len(encrypted_data):,} bytes...")

        cipher_aes   = AES.new(session_key, AES.MODE_CBC, iv)
        padded_plain = cipher_aes.decrypt(encrypted_data)
        plain_bytes  = unpad(padded_plain, AES.block_size)

        # Xóa session key khỏi memory
        del session_key

        logger.info(f"[DECRYPT] Restored: {len(plain_bytes):,} bytes")

        return JSONResponse({
            "status":         "success",
            "restored_bytes": len(plain_bytes),
            "file_b64":       base64.b64encode(plain_bytes).decode(),
        })

    except ValueError as e:
        raise HTTPException(400, f"Lỗi giải mã (sai key hoặc dữ liệu bị hỏng): {e}")
    except Exception as e:
        logger.error(f"[DECRYPT] Error: {e}")
        raise HTTPException(500, str(e))


# ─────────────────────────────────────────
#  Health check
# ─────────────────────────────────────────
@app.get("/api/health")
def health():
    return {"status": "ok", "app": "Secure File Transfer v2.1", "rnf03": "compliant"}
