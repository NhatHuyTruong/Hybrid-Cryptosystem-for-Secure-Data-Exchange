"""
=============================================================
  Secure File Transfer — Backend API (FastAPI)
  Phase 2 | Trương Nhật Huy — MSSV 22127168
=============================================================
  Modules:
    - /api/keys/generate      → Sinh cặp khóa RSA-2048
    - /api/encrypt            → Alice: ký số + mã hóa + đóng gói
    - /api/decrypt            → Bob: giải mã + xác thực chữ ký
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
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# ─────────────────────────────────────────
#  App setup
# ─────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Secure File Transfer API",
    description="Hybrid Cryptosystem & Digital Signature — Phase 2",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend tĩnh
app.mount("/static", StaticFiles(directory="../frontend/static"), name="static")


# ─────────────────────────────────────────
#  Serve index.html
# ─────────────────────────────────────────
@app.get("/")
def serve_index():
    return FileResponse("../frontend/index.html")


# ─────────────────────────────────────────
#  MODULE 1: Quản lý Khóa (Key Manager)
# ─────────────────────────────────────────
@app.post("/api/keys/generate")
def generate_keypair(bits: int = 2048):
    """
    Sinh cặp khóa RSA mới.
    - bits: độ dài khóa (tối thiểu 2048 theo spec)
    - Trả về private_key và public_key dạng PEM (base64)
    """
    if bits < 2048:
        raise HTTPException(400, "Độ dài khóa tối thiểu phải là 2048-bit theo tiêu chuẩn bảo mật.")

    logger.info(f"Generating RSA-{bits} keypair...")
    key = RSA.generate(bits)

    private_pem = key.export_key("PEM").decode()
    public_pem  = key.publickey().export_key("PEM").decode()

    logger.info("Keypair generated successfully.")
    return {
        "status":      "success",
        "bits":        bits,
        "private_key": private_pem,
        "public_key":  public_pem,
    }


# ─────────────────────────────────────────
#  MODULE 2: Alice — Mã hóa & Đóng gói
# ─────────────────────────────────────────
@app.post("/api/encrypt")
async def encrypt_file(
    file:            UploadFile = File(...,  description="Tập tin gốc cần mã hóa"),
    alice_private:   UploadFile = File(...,  description="Private Key của Alice (.pem) — dùng để ký số"),
    bob_public:      UploadFile = File(...,  description="Public Key của Bob (.pem) — dùng để mã hóa Session Key"),
):
    """
    Luồng mã hóa phía Alice:
      1. Đọc file gốc
      2. Băm (SHA-256) → Ký số (RSA + PKCS#1 v1.5) bằng PrivKey Alice
      3. Sinh Session Key ngẫu nhiên (AES-256)
      4. Mã hóa file bằng AES-256-CBC + PKCS#7
      5. Mã hóa Session Key bằng RSA-OAEP (PubKey Bob)
      6. Đóng gói 3 thành phần thành 1 file .pkg
    """
    try:
        # ── Đọc dữ liệu đầu vào ──
        file_bytes     = await file.read()
        alice_priv_pem = await alice_private.read()
        bob_pub_pem    = await bob_public.read()

        logger.info(f"[ENCRYPT] File: '{file.filename}' ({len(file_bytes):,} bytes)")

        # ── Bước 2: Ký số (Digital Signature) ──
        logger.info("[ENCRYPT] Step 2: Computing SHA-256 hash...")
        h = SHA256.new(file_bytes)
        file_hash_hex = h.hexdigest()

        logger.info("[ENCRYPT] Step 2: Signing with Alice's Private Key (RSA PKCS#1 v1.5)...")
        alice_key = RSA.import_key(alice_priv_pem)
        signature = pkcs1_15.new(alice_key).sign(h)   # bytes

        # ── Bước 3: Sinh Session Key & mã hóa AES ──
        logger.info("[ENCRYPT] Step 3: Generating random AES-256 Session Key...")
        session_key = get_random_bytes(32)             # 256-bit
        iv          = get_random_bytes(16)             # 128-bit IV

        logger.info("[ENCRYPT] Step 3: Encrypting file with AES-256-CBC + PKCS#7...")
        cipher_aes      = AES.new(session_key, AES.MODE_CBC, iv)
        padded_data     = pad(file_bytes, AES.block_size)
        encrypted_data  = cipher_aes.encrypt(padded_data)

        # ── Bước 4: Mã hóa Session Key bằng RSA-OAEP ──
        logger.info("[ENCRYPT] Step 4: Encrypting Session Key with Bob's Public Key (RSA-OAEP)...")
        bob_key          = RSA.import_key(bob_pub_pem)
        cipher_rsa       = PKCS1_OAEP.new(bob_key)
        encrypted_sk     = cipher_rsa.encrypt(session_key)

        # ── Bước 5: Đóng gói (Binary Package Format) ──
        #
        #  Package layout:
        #  ┌──────────────────────────────────────────────┐
        #  │ MAGIC (8B) | VERSION (1B)                     │
        #  │ orig_filename_len (4B) | orig_filename (N)    │
        #  │ sig_len (4B)           | signature (M)        │
        #  │ enc_sk_len (4B)        | encrypted_sk (256B)  │
        #  │ iv (16B)                                      │
        #  │ enc_data_len (4B)      | encrypted_data (K)   │
        #  └──────────────────────────────────────────────┘
        #
        logger.info("[ENCRYPT] Step 5: Packaging all components...")
        MAGIC   = b"SFTPKG02"
        VERSION = b"\x01"

        orig_name_bytes = file.filename.encode("utf-8")

        pkg = io.BytesIO()
        pkg.write(MAGIC)
        pkg.write(VERSION)
        pkg.write(struct.pack(">I", len(orig_name_bytes)));  pkg.write(orig_name_bytes)
        pkg.write(struct.pack(">I", len(signature)));        pkg.write(signature)
        pkg.write(struct.pack(">I", len(encrypted_sk)));     pkg.write(encrypted_sk)
        pkg.write(iv)
        pkg.write(struct.pack(">I", len(encrypted_data)));   pkg.write(encrypted_data)

        pkg_bytes = pkg.getvalue()
        logger.info(f"[ENCRYPT] Done. Package size: {len(pkg_bytes):,} bytes")

        return JSONResponse({
            "status":        "success",
            "original_file": file.filename,
            "file_hash_sha256": file_hash_hex,
            "session_key_bits": 256,
            "signature_bytes":  len(signature),
            "package_bytes":    len(pkg_bytes),
            "package_b64":      base64.b64encode(pkg_bytes).decode(),
        })

    except ValueError as e:
        logger.error(f"[ENCRYPT] Key error: {e}")
        raise HTTPException(400, f"Sai định dạng khóa: {str(e)}")
    except Exception as e:
        logger.error(f"[ENCRYPT] Unexpected error: {e}")
        raise HTTPException(500, f"Lỗi mã hóa: {str(e)}")


# ─────────────────────────────────────────
#  MODULE 3: Bob — Giải mã & Xác thực
# ─────────────────────────────────────────
@app.post("/api/decrypt")
async def decrypt_file(
    package:       UploadFile = File(..., description="Tập tin gói mã hóa (.pkg)"),
    bob_private:   UploadFile = File(..., description="Private Key của Bob (.pem) — giải mã Session Key"),
    alice_public:  UploadFile = File(..., description="Public Key của Alice (.pem) — xác thực chữ ký số"),
):
    """
    Luồng giải mã phía Bob:
      1. Tách lớp gói (unpack)
      2. Giải mã Session Key (RSA-OAEP + PrivKey Bob)
      3. Giải mã dữ liệu (AES-256-CBC)
      4. Xác thực chữ ký: hash lại → so sánh vs signature (PubKey Alice)
      5. Trả về file gốc + kết quả xác thực
    """
    try:
        pkg_bytes      = await package.read()
        bob_priv_pem   = await bob_private.read()
        alice_pub_pem  = await alice_public.read()

        logger.info(f"[DECRYPT] Package size: {len(pkg_bytes):,} bytes")

        # ── Bước 1: Tách lớp (Unpack) ──
        logger.info("[DECRYPT] Step 1: Unpacking package...")
        MAGIC   = b"SFTPKG02"
        buf     = io.BytesIO(pkg_bytes)

        magic = buf.read(8)
        if magic != MAGIC:
            raise ValueError("File không phải là gói hợp lệ (sai magic bytes). File bị hỏng hoặc sai định dạng.")

        version = buf.read(1)

        orig_name_len = struct.unpack(">I", buf.read(4))[0]
        orig_filename = buf.read(orig_name_len).decode("utf-8")

        sig_len   = struct.unpack(">I", buf.read(4))[0]
        signature = buf.read(sig_len)

        enc_sk_len   = struct.unpack(">I", buf.read(4))[0]
        encrypted_sk = buf.read(enc_sk_len)

        iv           = buf.read(16)

        enc_data_len    = struct.unpack(">I", buf.read(4))[0]
        encrypted_data  = buf.read(enc_data_len)

        logger.info(f"[DECRYPT] Unpacked: file='{orig_filename}', sig={sig_len}B, enc_sk={enc_sk_len}B, data={enc_data_len}B")

        # ── Bước 2: Giải mã Session Key ──
        logger.info("[DECRYPT] Step 2: Decrypting Session Key with Bob's Private Key (RSA-OAEP)...")
        bob_key      = RSA.import_key(bob_priv_pem)
        cipher_rsa   = PKCS1_OAEP.new(bob_key)
        session_key  = cipher_rsa.decrypt(encrypted_sk)

        # ── Bước 3: Giải mã dữ liệu ──
        logger.info("[DECRYPT] Step 3: Decrypting file data with AES-256-CBC...")
        cipher_aes   = AES.new(session_key, AES.MODE_CBC, iv)
        padded_plain = cipher_aes.decrypt(encrypted_data)
        plain_bytes  = unpad(padded_plain, AES.block_size)

        logger.info(f"[DECRYPT] File restored: {len(plain_bytes):,} bytes")

        # ── Bước 4: Xác thực chữ ký số ──
        logger.info("[DECRYPT] Step 4: Verifying digital signature (SHA-256 + RSA PKCS#1 v1.5)...")
        h = SHA256.new(plain_bytes)
        computed_hash = h.hexdigest()

        alice_key = RSA.import_key(alice_pub_pem)
        integrity_ok = False
        integrity_msg = ""
        try:
            pkcs1_15.new(alice_key).verify(h, signature)
            integrity_ok  = True
            integrity_msg = "Hợp lệ — Dữ liệu toàn vẹn (Integrity Verified)"
            logger.info("[DECRYPT] ✅ Signature VALID")
        except (ValueError, TypeError):
            integrity_ok  = False
            integrity_msg = "CẢNH BÁO: Dữ liệu bị thay đổi hoặc sai khóa! (Tampered / Wrong Key)"
            logger.warning("[DECRYPT] ❌ Signature INVALID")

        return JSONResponse({
            "status":          "success",
            "original_file":   orig_filename,
            "restored_bytes":  len(plain_bytes),
            "computed_hash":   computed_hash,
            "integrity_ok":    integrity_ok,
            "integrity_msg":   integrity_msg,
            "file_b64":        base64.b64encode(plain_bytes).decode(),
        })

    except struct.error:
        raise HTTPException(400, "File bị hỏng — không thể đọc cấu trúc gói (struct error).")
    except ValueError as e:
        raise HTTPException(400, f"Lỗi: {str(e)}")
    except Exception as e:
        logger.error(f"[DECRYPT] Unexpected: {e}")
        raise HTTPException(500, f"Lỗi giải mã: {str(e)}")


# ─────────────────────────────────────────
#  Health check
# ─────────────────────────────────────────
@app.get("/api/health")
def health():
    return {"status": "ok", "app": "Secure File Transfer v2.0"}
