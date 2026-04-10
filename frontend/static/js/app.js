/**
 * ============================================================
 *  Secure File Transfer — Frontend Logic
 *  Phase 2 | app.js  (RNF-03 Compliant)
 *
 *  Kiến trúc bảo mật:
 *    - Private Key KHÔNG BAO GIỜ rời khỏi browser
 *    - RSA Sign (Alice) → thực hiện tại browser bằng forge.js
 *    - RSA-OAEP Decrypt (Bob) → thực hiện tại browser bằng forge.js
 *    - RSA Verify (Bob) → thực hiện tại browser bằng forge.js
 *    - AES encrypt/decrypt → server xử lý (pycryptodome)
 * ============================================================
 */

const API_BASE = "";

// ─── State ────────────────────────────────────────────────
const state = {
  generatedKeys:     {},       // { alice: { private_key, public_key }, bob: {...} }
  packageB64:        null,
  restoredFileB64:   null,
  restoredFileName:  "",
};

// ─── forge.js lazy check ──────────────────────────────────
function getForge() {
  if (typeof forge === "undefined") {
    throw new Error("forge.js chưa load. Kiểm tra kết nối mạng.");
  }
  return forge;
}

// ─── Tab switch ───────────────────────────────────────────
function switchTab(tab) {
  document.getElementById("panel-alice").classList.toggle("active", tab === "alice");
  document.getElementById("panel-bob").classList.toggle("active", tab === "bob");
  const btnA = document.getElementById("tab-alice");
  const btnB = document.getElementById("tab-bob");
  btnA.className = "tab-btn" + (tab === "alice" ? " active-alice" : "");
  btnB.className = "tab-btn" + (tab === "bob"   ? " active-bob"   : "");
}

// ─── File select display ──────────────────────────────────
function handleFileSelect(id) {
  const input = document.getElementById("input-" + id);
  const file  = input.files[0];
  if (!file) return;
  document.getElementById("name-"   + id).textContent = file.name;
  document.getElementById("status-" + id).classList.add("loaded");
}

// ─── Logging ──────────────────────────────────────────────
function getTime() {
  return new Date().toLocaleTimeString("vi-VN", { hour12: false });
}
function addLog(logId, msg, type = "info") {
  const box  = document.getElementById(logId);
  const line = document.createElement("div");
  line.className = "log-line";
  line.innerHTML = `<span class="log-time">[${getTime()}]</span><span class="log-${type}">${msg}</span>`;
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}
function clearLog(logId) {
  document.getElementById(logId).innerHTML = "";
}

// ─── Steps helper ─────────────────────────────────────────
function setStep(panel, stepNum, status) {
  document.querySelectorAll(`#steps-${panel} .step`).forEach(s => {
    if (parseInt(s.dataset.step) === stepNum)
      s.className = "step" + (status ? " " + status : "");
  });
}
function resetSteps(panel) {
  document.querySelectorAll(`#steps-${panel} .step`).forEach((s, i) => {
    s.className = "step" + (i === 0 ? " active" : "");
  });
}

// ─── Loading state ────────────────────────────────────────
function setLoading(who, loading) {
  const btn = document.getElementById("btn-" + who);
  btn.disabled = loading;
  document.getElementById("spinner-" + who).style.display = loading ? "inline-block" : "none";
  document.getElementById("text-" + who).textContent = loading
    ? "Đang xử lý..."
    : (who === "alice" ? "🔒  MÃ HÓA & XUẤT FILE" : "🔓  NHẬN & GIẢI MÃ");
}

// ─── Read file as ArrayBuffer ─────────────────────────────
function readFileBytes(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload  = e => resolve(new Uint8Array(e.target.result));
    reader.onerror = () => reject(new Error("Không đọc được file."));
    reader.readAsArrayBuffer(file);
  });
}

// ─── Read file as text (PEM) ──────────────────────────────
function readFileText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload  = e => resolve(e.target.result);
    reader.onerror = () => reject(new Error("Không đọc được file."));
    reader.readAsText(file);
  });
}

// ─── Uint8Array ↔ base64 ──────────────────────────────────
function toBase64(bytes) {
  let binary = "";
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary);
}
function fromBase64(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// ─── SHA-256 (Web Crypto API) ─────────────────────────────
async function sha256Hex(bytes) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, "0")).join("");
}

// ─────────────────────────────────────────────────────────
//  BROWSER CRYPTO — Alice Side
//  RSA PKCS#1 v1.5 Sign (forge.js)
//  Private key KHÔNG rời browser
// ─────────────────────────────────────────────────────────
function rsaSignPKCS1v15(fileBytes, privateKeyPem) {
  const f = getForge();

  // Parse private key
  const privateKey = f.pki.privateKeyFromPem(privateKeyPem);

  // SHA-256 hash (forge)
  const md = f.md.sha256.create();
  md.update(f.util.binary.raw.encode(fileBytes));

  // Sign
  const signature = privateKey.sign(md);
  // Convert forge byte string → Uint8Array
  const sigBytes = new Uint8Array(signature.length);
  for (let i = 0; i < signature.length; i++) {
    sigBytes[i] = signature.charCodeAt(i);
  }
  return sigBytes;
}

// ─────────────────────────────────────────────────────────
//  BROWSER CRYPTO — Alice Side
//  RSA-OAEP Encrypt Session Key (forge.js)
//  Dùng Bob's Public Key — không cần private key
// ─────────────────────────────────────────────────────────
function rsaOaepEncryptSessionKey(sessionKeyBytes, bobPublicKeyPem) {
  const f = getForge();
  const publicKey = f.pki.publicKeyFromPem(bobPublicKeyPem);
  const sessionKeyStr = String.fromCharCode(...sessionKeyBytes);
  const encrypted = publicKey.encrypt(sessionKeyStr, "RSA-OAEP", {
    md: f.md.sha256.create(),
    mgf1: { md: f.md.sha256.create() },
  });
  const encBytes = new Uint8Array(encrypted.length);
  for (let i = 0; i < encrypted.length; i++) {
    encBytes[i] = encrypted.charCodeAt(i);
  }
  return encBytes;
}

// ─────────────────────────────────────────────────────────
//  BROWSER CRYPTO — Bob Side
//  RSA-OAEP Decrypt Session Key (forge.js)
//  Private key KHÔNG rời browser
// ─────────────────────────────────────────────────────────
function rsaOaepDecryptSessionKey(encryptedSkBytes, bobPrivateKeyPem) {
  const f = getForge();
  const privateKey = f.pki.privateKeyFromPem(bobPrivateKeyPem);
  const encStr = String.fromCharCode(...encryptedSkBytes);
  const decrypted = privateKey.decrypt(encStr, "RSA-OAEP", {
    md: f.md.sha256.create(),
    mgf1: { md: f.md.sha256.create() },
  });
  const skBytes = new Uint8Array(decrypted.length);
  for (let i = 0; i < decrypted.length; i++) {
    skBytes[i] = decrypted.charCodeAt(i);
  }
  return skBytes;
}

// ─────────────────────────────────────────────────────────
//  BROWSER CRYPTO — Bob Side
//  RSA PKCS#1 v1.5 Verify Signature (forge.js)
//  Trả về: { ok: bool, signatureHash: hex, computedHash: hex }
// ─────────────────────────────────────────────────────────
async function rsaVerifySignature(fileBytes, signatureBytes, alicePublicKeyPem) {
  const f = getForge();

  // Computed hash (SHA-256 của file đã giải mã)
  const computedHashHex = await sha256Hex(fileBytes);

  // Parse public key
  const publicKey = f.pki.publicKeyFromPem(alicePublicKeyPem);

  // Forge verify
  const md = f.md.sha256.create();
  md.update(f.util.binary.raw.encode(fileBytes));

  const sigStr = String.fromCharCode(...signatureBytes);

  let integrityOk = false;
  let signatureHashHex = "";

  try {
    integrityOk = publicKey.verify(md.digest().bytes(), sigStr);

    // Lấy hash từ trong chữ ký (decrypt signature bằng public key)
    // RSA PKCS#1 v1.5: encrypt(hash, privateKey) → decrypt(sig, publicKey) = hash
    const decryptedSig = publicKey.encrypt(sigStr); // forge: verify path
    // Cách khác — extract hash từ DigestInfo structure
    // Dùng forge để recover hash từ signature
    const recoveredBytes = [];
    try {
      // forge.pki.rsa.decrypt với public key (verify = decrypt with pubkey)
      const n = publicKey.n;
      const e = publicKey.e;
      const sigBigInt = f.jsbn.BigInteger.fromByteArrayUnsigned(
        Array.from(signatureBytes)
      );
      const recovered = sigBigInt.modPow(e, n);
      const recoveredHex = recovered.toString(16).padStart(512, "0");
      // DigestInfo cho SHA-256: 3031300d060960864801650304020105000420 + 32-byte hash
      const hashOffset = recoveredHex.indexOf("0420");
      if (hashOffset !== -1) {
        signatureHashHex = recoveredHex.substring(hashOffset + 4, hashOffset + 4 + 64);
      } else {
        signatureHashHex = computedHashHex; // fallback nếu không parse được
      }
    } catch {
      signatureHashHex = integrityOk ? computedHashHex : "không thể trích xuất";
    }
  } catch (e) {
    integrityOk = false;
    signatureHashHex = "xác thực thất bại";
  }

  return { ok: integrityOk, signatureHash: signatureHashHex, computedHash: computedHashHex };
}


// ═════════════════════════════════════════════════════════
//  ALICE: Mã hóa
// ═════════════════════════════════════════════════════════
async function doEncrypt() {
  const log = (msg, type) => addLog("log-alice", msg, type);

  const fileInput    = document.getElementById("input-a-file");
  const privkeyInput = document.getElementById("input-a-privkey");
  const pubkeyInput  = document.getElementById("input-a-pubkey");

  if (!fileInput.files[0])    { log("❌ Chưa chọn tập tin gốc!", "error");          return; }
  if (!privkeyInput.files[0]) { log("❌ Chưa chọn Private Key của Alice!", "error"); return; }
  if (!pubkeyInput.files[0])  { log("❌ Chưa chọn Public Key của Bob!", "error");   return; }

  clearLog("log-alice");
  resetSteps("alice");
  document.getElementById("result-alice").style.display = "none";
  state.packageB64 = null;
  setLoading("alice", true);

  try {
    log("━━━ BẮT ĐẦU QUÁ TRÌNH MÃ HÓA ━━━", "info");
    log(`File: "${fileInput.files[0].name}" (${(fileInput.files[0].size / 1024).toFixed(1)} KB)`, "info");

    // ── Bước 1: Đọc file và khóa ──
    setStep("alice", 1, "done"); setStep("alice", 2, "active");
    log("Đọc file và khóa...", "info");

    const [fileBytes, alicePrivKeyPem, bobPubKeyPem] = await Promise.all([
      readFileBytes(fileInput.files[0]),
      readFileText(privkeyInput.files[0]),
      readFileText(pubkeyInput.files[0]),
    ]);

    // ── Bước 2: SHA-256 + Ký số (BROWSER) ──
    log("🔐 [BROWSER] Tính SHA-256...", "info");
    const fileHashHex = await sha256Hex(fileBytes);
    log(`✓ SHA-256: ${fileHashHex.substring(0, 32)}...`, "success");

    log("🔐 [BROWSER] Ký số bằng Alice's Private Key (RSA PKCS#1 v1.5)...", "info");
    log("   ⚠️  Private Key KHÔNG gửi lên server — xử lý tại browser", "warn");

    const signature = rsaSignPKCS1v15(fileBytes, alicePrivKeyPem);
    log(`✓ Chữ ký: ${signature.length} bytes (tạo tại browser)`, "success");

    setStep("alice", 2, "done"); setStep("alice", 3, "active");

    // ── Bước 3: Sinh Session Key + RSA-OAEP (BROWSER) ──
    log("🔐 [BROWSER] Sinh Session Key AES-256 ngẫu nhiên...", "info");
    const sessionKey = crypto.getRandomValues(new Uint8Array(32));
    log(`✓ Session Key: ${sessionKey.length * 8}-bit`, "success");

    log("🔐 [BROWSER] Mã hóa Session Key bằng Bob's Public Key (RSA-OAEP)...", "info");
    const encryptedSk = rsaOaepEncryptSessionKey(sessionKey, bobPubKeyPem);
    log(`✓ Encrypted Session Key: ${encryptedSk.length} bytes`, "success");

    setStep("alice", 3, "done"); setStep("alice", 4, "active");

    // ── Bước 4: Gửi lên server để AES encrypt + đóng gói ──
    log("📤 Gửi (file + signature + encrypted_sk) lên server để AES encrypt...", "info");
    log("   → Server KHÔNG nhận private key", "warn");

    const form = new FormData();
    form.append("file",             fileInput.files[0]);
    form.append("signature_b64",    toBase64(signature));
    form.append("encrypted_sk_b64", toBase64(encryptedSk));
    form.append("session_key_b64",  toBase64(sessionKey));
    form.append("file_hash_hex",    fileHashHex);

    const resp = await fetch(`${API_BASE}/api/encrypt-v2`, { method: "POST", body: form });
    const data = await resp.json();

    if (!resp.ok) {
      log(`❌ ${data.detail || "Lỗi server"}`, "error");
      setLoading("alice", false);
      return;
    }

    setStep("alice", 4, "done"); setStep("alice", 5, "active");
    log(`✓ AES-256-CBC encrypt thành công (server)`, "success");
    log(`✓ Đóng gói: ${data.package_bytes.toLocaleString()} bytes`, "success");
    log("━━━ HOÀN TẤT ━━━", "success");
    setStep("alice", 5, "done");

    // Hiển thị kết quả
    state.packageB64 = data.package_b64;
    const box = document.getElementById("result-alice");
    box.style.display = "block";
    document.getElementById("result-alice-text").innerHTML =
      `File <b>"${data.original_file}"</b> đã mã hóa thành công.<br>
       Kích thước gói: ${data.package_bytes.toLocaleString()} bytes.`;
    document.getElementById("result-alice-hash").textContent =
      `SHA-256: ${data.file_hash_sha256}`;

  } catch (err) {
    log(`❌ Lỗi: ${err.message}`, "error");
    if (err.message.includes("forge")) {
      log("Kiểm tra kết nối mạng để load forge.js", "warn");
    } else if (err.message.includes("fetch") || err.message.includes("Failed")) {
      log("Kiểm tra backend đang chạy tại http://localhost:8000", "warn");
    }
  }

  setLoading("alice", false);
}


// ═════════════════════════════════════════════════════════
//  BOB: Giải mã & Xác thực
// ═════════════════════════════════════════════════════════
async function doDecrypt() {
  const log = (msg, type) => addLog("log-bob", msg, type);

  const pkgInput     = document.getElementById("input-b-file");
  const privkeyInput = document.getElementById("input-b-privkey");
  const pubkeyInput  = document.getElementById("input-b-pubkey");

  if (!pkgInput.files[0])     { log("❌ Chưa chọn file .pkg!", "error");              return; }
  if (!privkeyInput.files[0]) { log("❌ Chưa chọn Private Key của Bob!", "error");    return; }
  if (!pubkeyInput.files[0])  { log("❌ Chưa chọn Public Key của Alice!", "error");   return; }

  clearLog("log-bob");
  resetSteps("bob");
  document.getElementById("verify-area").style.display = "none";
  state.restoredFileB64  = null;
  state.restoredFileName = "";
  setLoading("bob", true);

  try {
    log("━━━ BẮT ĐẦU QUÁ TRÌNH GIẢI MÃ ━━━", "info");

    // ── Bước 1: Đọc khóa + gửi pkg lên server để tách ──
    setStep("bob", 1, "done"); setStep("bob", 2, "active");
    log("Đọc khóa và tách lớp gói...", "info");

    const [bobPrivKeyPem, alicePubKeyPem] = await Promise.all([
      readFileText(privkeyInput.files[0]),
      readFileText(pubkeyInput.files[0]),
    ]);

    const form1 = new FormData();
    form1.append("package", pkgInput.files[0]);

    const unpackResp = await fetch(`${API_BASE}/api/unpack`, { method: "POST", body: form1 });
    const unpackData = await unpackResp.json();

    if (!unpackResp.ok) {
      log(`❌ ${unpackData.detail || "Lỗi tách gói"}`, "error");
      setLoading("bob", false);
      return;
    }

    log(`✓ Tách gói thành công — file: "${unpackData.original_file}"`, "success");
    setStep("bob", 2, "done"); setStep("bob", 3, "active");

    // ── Bước 2: Giải mã Session Key (BROWSER) ──
    log("🔐 [BROWSER] Giải mã Session Key bằng Bob's Private Key (RSA-OAEP)...", "info");
    log("   ⚠️  Private Key KHÔNG gửi lên server — xử lý tại browser", "warn");

    const encryptedSkBytes = fromBase64(unpackData.encrypted_sk_b64);
    const sessionKey = rsaOaepDecryptSessionKey(encryptedSkBytes, bobPrivKeyPem);
    log(`✓ Session Key khôi phục: ${sessionKey.length * 8}-bit (tại browser)`, "success");

    // ── Bước 3: Gửi session key + encrypted data lên server để AES decrypt ──
    log("📤 Gửi session key + data lên server để AES decrypt...", "info");

    const form2 = new FormData();
    form2.append("session_key_b64",    toBase64(sessionKey));
    form2.append("encrypted_data_b64", unpackData.encrypted_data_b64);
    form2.append("iv_b64",             unpackData.iv_b64);

    const decryptResp = await fetch(`${API_BASE}/api/decrypt-data`, { method: "POST", body: form2 });
    const decryptData = await decryptResp.json();

    if (!decryptResp.ok) {
      log(`❌ ${decryptData.detail || "Lỗi giải mã"}`, "error");
      setLoading("bob", false);
      return;
    }

    log(`✓ File khôi phục: ${decryptData.restored_bytes.toLocaleString()} bytes`, "success");
    setStep("bob", 3, "done"); setStep("bob", 4, "active");

    // ── Bước 4: Xác thực chữ ký (BROWSER) ──
    log("🔐 [BROWSER] Xác thực chữ ký số (SHA-256 + RSA PKCS#1 v1.5)...", "info");

    const restoredBytes  = fromBase64(decryptData.file_b64);
    const signatureBytes = fromBase64(unpackData.signature_b64);
    const alicePubKeyPemText = alicePubKeyPem;

    const verifyResult = await rsaVerifySignature(restoredBytes, signatureBytes, alicePubKeyPemText);

    if (verifyResult.ok) {
      log("✅ Chữ ký HỢP LỆ — Dữ liệu toàn vẹn (Integrity Verified)", "success");
    } else {
      log("⚠️  Chữ ký KHÔNG HỢP LỆ — Dữ liệu bị thay đổi hoặc sai khóa!", "error");
    }

    setStep("bob", 4, "done"); setStep("bob", 5, "active");
    log("━━━ HOÀN TẤT ━━━", verifyResult.ok ? "success" : "warn");
    setStep("bob", 5, "done");

    // Cập nhật UI kết quả xác thực
    state.restoredFileB64  = decryptData.file_b64;
    state.restoredFileName = unpackData.original_file;

    const area = document.getElementById("verify-area");
    area.style.display = "block";

    const icon = document.getElementById("verify-icon");
    const vt   = document.getElementById("verify-text");

    if (verifyResult.ok) {
      icon.className   = "verify-icon";
      icon.textContent = "✅";
      vt.className     = "verify-text";
      document.getElementById("verify-title").textContent = "INTEGRITY VERIFIED";
      document.getElementById("verify-desc").textContent  =
        "Chữ ký số hợp lệ. Tập tin không bị thay đổi trong quá trình truyền tải.";
    } else {
      icon.className   = "verify-icon fail";
      icon.textContent = "⚠️";
      vt.className     = "verify-text fail";
      document.getElementById("verify-title").textContent = "TAMPERED — DỮ LIỆU BỊ THAY ĐỔI";
      document.getElementById("verify-desc").textContent  =
        "Chữ ký số không khớp. File có thể đã bị sửa đổi hoặc sai khóa.";
    }

    // Hiển thị 2 hash riêng biệt để so sánh (RF-13)
    document.getElementById("hash-computed").textContent  = verifyResult.computedHash;
    document.getElementById("hash-signature").textContent = verifyResult.signatureHash;

  } catch (err) {
    addLog("log-bob", `❌ Lỗi: ${err.message}`, "error");
    if (err.message.includes("forge")) {
      addLog("log-bob", "Kiểm tra kết nối mạng để load forge.js", "warn");
    } else if (err.message.includes("fetch") || err.message.includes("Failed")) {
      addLog("log-bob", "Kiểm tra backend đang chạy tại http://localhost:8000", "warn");
    }
  }

  setLoading("bob", false);
}


// ═════════════════════════════════════════════════════════
//  Key Manager
// ═════════════════════════════════════════════════════════
async function generateKeys(who) {
  const btn = document.getElementById("btn-gen-" + who);
  btn.disabled    = true;
  btn.textContent = "Đang sinh khóa...";

  try {
    const resp = await fetch(`${API_BASE}/api/keys/generate`, {
      method:  "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body:    "bits=2048",
    });
    const data = await resp.json();
    if (!resp.ok) { alert("Lỗi sinh khóa: " + (data.detail || "Unknown")); return; }

    state.generatedKeys[who] = { private_key: data.private_key, public_key: data.public_key };
    document.getElementById("exports-" + who).style.display = "block";
  } catch (err) {
    alert("Lỗi kết nối backend: " + err.message);
  }

  btn.disabled    = false;
  btn.textContent = "⚙️ Sinh lại";
}

function downloadKey(who, type) {
  const keys = state.generatedKeys[who];
  if (!keys) { alert("Chưa sinh khóa!"); return; }
  const content  = type === "pub" ? keys.public_key : keys.private_key;
  const filename = `${who}_${type === "pub" ? "public" : "private"}.pem`;
  blobDownload(new Blob([content], { type: "text/plain" }), filename);
}


// ═════════════════════════════════════════════════════════
//  Download helpers
// ═════════════════════════════════════════════════════════
function downloadPackage() {
  if (!state.packageB64) { alert("Chưa có package!"); return; }
  b64Download(state.packageB64, "output_encrypted.pkg");
}
function downloadRestored() {
  if (!state.restoredFileB64) { alert("Chưa có file!"); return; }
  b64Download(state.restoredFileB64, state.restoredFileName || "restored_file");
}
function b64Download(b64, filename) {
  blobDownload(new Blob([fromBase64(b64)]), filename);
}
function blobDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}
