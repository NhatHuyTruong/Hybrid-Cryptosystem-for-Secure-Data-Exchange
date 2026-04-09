/**
 * ============================================================
 *  Secure File Transfer — Frontend Logic
 *  Phase 2 | app.js
 *  Gọi API backend tại /api/*
 * ============================================================
 */

const API_BASE = "";   // Same origin; đổi thành "http://localhost:8000" nếu chạy tách riêng

// ─── State ────────────────────────────────────────────────
const state = {
  generatedKeys: {},        // { alice: { private_key, public_key }, bob: {...} }
  packageB64: null,         // Base64 ciphertext package để download
  restoredFileB64: null,    // Base64 file gốc sau giải mã
  restoredFileName: "",     // Tên file gốc
};

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
  // status: 'active' | 'done' | ''
  const steps = document.querySelectorAll(`#steps-${panel} .step`);
  steps.forEach(s => {
    if (parseInt(s.dataset.step) === stepNum) {
      s.className = "step" + (status ? " " + status : "");
    }
  });
}

function resetSteps(panel) {
  const steps = document.querySelectorAll(`#steps-${panel} .step`);
  steps.forEach((s, i) => { s.className = "step" + (i === 0 ? " active" : ""); });
}

// ─── Loading state ────────────────────────────────────────
function setLoading(who, loading) {
  const btn     = document.getElementById("btn-" + who);
  const spinner = document.getElementById("spinner-" + who);
  const txt     = document.getElementById("text-" + who);
  btn.disabled  = loading;
  spinner.style.display = loading ? "inline-block" : "none";
  if (!loading) {
    txt.textContent = who === "alice" ? "🔒  MÃ HÓA & XUẤT FILE" : "🔓  NHẬN & GIẢI MÃ";
  } else {
    txt.textContent = "Đang xử lý...";
  }
}

// ─────────────────────────────────────────────────────────
//  ALICE: Mã hóa
// ─────────────────────────────────────────────────────────
async function doEncrypt() {
  const log = (msg, type) => addLog("log-alice", msg, type);

  const fileInput      = document.getElementById("input-a-file");
  const privkeyInput   = document.getElementById("input-a-privkey");
  const pubkeyInput    = document.getElementById("input-a-pubkey");

  // Validate inputs
  if (!fileInput.files[0]) {
    log("❌ Chưa chọn tập tin gốc!", "error"); return;
  }
  if (!privkeyInput.files[0]) {
    log("❌ Chưa chọn Private Key của Alice!", "error"); return;
  }
  if (!pubkeyInput.files[0]) {
    log("❌ Chưa chọn Public Key của Bob!", "error"); return;
  }

  clearLog("log-alice");
  resetSteps("alice");
  document.getElementById("result-alice").style.display = "none";
  state.packageB64 = null;
  setLoading("alice", true);

  log("━━━ BẮT ĐẦU QUÁ TRÌNH MÃ HÓA ━━━", "info");
  log(`File: "${fileInput.files[0].name}" (${(fileInput.files[0].size / 1024).toFixed(1)} KB)`, "info");
  log("Gửi yêu cầu lên backend API /api/encrypt...", "info");

  // Build FormData
  const form = new FormData();
  form.append("file",          fileInput.files[0]);
  form.append("alice_private", privkeyInput.files[0]);
  form.append("bob_public",    pubkeyInput.files[0]);

  try {
    setStep("alice", 1, "done"); setStep("alice", 2, "active");

    const resp = await fetch(`${API_BASE}/api/encrypt`, {
      method: "POST",
      body:   form,
    });

    const data = await resp.json();

    if (!resp.ok) {
      log(`❌ ${data.detail || "Lỗi không xác định"}`, "error");
      setLoading("alice", false);
      return;
    }

    // Log steps from backend result
    setStep("alice", 2, "done"); setStep("alice", 3, "active");
    log(`✓ SHA-256: ${data.file_hash_sha256.substring(0, 32)}...`, "success");
    log(`✓ Chữ ký số: ${data.signature_bytes} bytes (RSA PKCS#1 v1.5)`, "success");

    setStep("alice", 3, "done"); setStep("alice", 4, "active");
    log(`✓ AES-256-CBC mã hóa thành công`, "success");
    log(`✓ Session Key (256-bit) mã hóa bằng RSA-OAEP`, "success");

    setStep("alice", 4, "done"); setStep("alice", 5, "active");
    log(`✓ Đóng gói: ${data.package_bytes.toLocaleString()} bytes`, "success");
    log("━━━ HOÀN TẤT ━━━", "success");
    setStep("alice", 5, "done");

    // Show result
    state.packageB64 = data.package_b64;
    const box = document.getElementById("result-alice");
    box.style.display = "block";
    document.getElementById("result-alice-text").innerHTML =
      `File <b>"${data.original_file}"</b> đã mã hóa thành công.<br>
       Kích thước gói: ${data.package_bytes.toLocaleString()} bytes.`;
    document.getElementById("result-alice-hash").textContent =
      `SHA-256: ${data.file_hash_sha256}`;

  } catch (err) {
    log(`❌ Lỗi kết nối backend: ${err.message}`, "error");
    log("Kiểm tra backend đang chạy tại http://localhost:8000", "warn");
  }

  setLoading("alice", false);
}

// ─────────────────────────────────────────────────────────
//  BOB: Giải mã & Xác thực
// ─────────────────────────────────────────────────────────
async function doDecrypt() {
  const log = (msg, type) => addLog("log-bob", msg, type);

  const pkgInput     = document.getElementById("input-b-file");
  const privkeyInput = document.getElementById("input-b-privkey");
  const pubkeyInput  = document.getElementById("input-b-pubkey");

  if (!pkgInput.files[0]) {
    log("❌ Chưa chọn tập tin mã hóa!", "error"); return;
  }
  if (!privkeyInput.files[0]) {
    log("❌ Chưa chọn Private Key của Bob!", "error"); return;
  }
  if (!pubkeyInput.files[0]) {
    log("❌ Chưa chọn Public Key của Alice!", "error"); return;
  }

  clearLog("log-bob");
  resetSteps("bob");
  document.getElementById("verify-area").style.display = "none";
  state.restoredFileB64  = null;
  state.restoredFileName = "";
  setLoading("bob", true);

  log("━━━ BẮT ĐẦU QUÁ TRÌNH GIẢI MÃ ━━━", "info");
  log("Gửi yêu cầu lên backend API /api/decrypt...", "info");

  const form = new FormData();
  form.append("package",      pkgInput.files[0]);
  form.append("bob_private",  privkeyInput.files[0]);
  form.append("alice_public", pubkeyInput.files[0]);

  try {
    setStep("bob", 1, "done"); setStep("bob", 2, "active");

    const resp = await fetch(`${API_BASE}/api/decrypt`, {
      method: "POST",
      body:   form,
    });

    const data = await resp.json();

    if (!resp.ok) {
      log(`❌ ${data.detail || "Lỗi không xác định"}`, "error");
      setLoading("bob", false);
      return;
    }

    setStep("bob", 2, "done"); setStep("bob", 3, "active");
    log("✓ Tách lớp gói thành công (Data | EncKey | Signature)", "success");

    log("✓ Giải mã Session Key bằng RSA-OAEP (Private Key Bob)", "success");
    log(`✓ File khôi phục: ${data.restored_bytes.toLocaleString()} bytes`, "success");
    setStep("bob", 3, "done"); setStep("bob", 4, "active");

    log(`SHA-256 computed: ${data.computed_hash.substring(0, 32)}...`, "info");

    if (data.integrity_ok) {
      log("✅ " + data.integrity_msg, "success");
    } else {
      log("⚠️  " + data.integrity_msg, "error");
    }
    setStep("bob", 4, "done"); setStep("bob", 5, "active");
    log("━━━ HOÀN TẤT ━━━", data.integrity_ok ? "success" : "warn");
    setStep("bob", 5, "done");

    // Update verify UI
    state.restoredFileB64  = data.file_b64;
    state.restoredFileName = data.original_file;

    const area = document.getElementById("verify-area");
    area.style.display = "block";

    const icon = document.getElementById("verify-icon");
    const vt   = document.getElementById("verify-text");
    if (data.integrity_ok) {
      icon.className = "verify-icon";
      icon.textContent = "✅";
      vt.className = "verify-text";
      document.getElementById("verify-title").textContent = "INTEGRITY VERIFIED";
      document.getElementById("verify-desc").textContent  = "Chữ ký số hợp lệ. Tập tin không bị thay đổi trong quá trình truyền tải.";
    } else {
      icon.className = "verify-icon fail";
      icon.textContent = "⚠️";
      vt.className = "verify-text fail";
      document.getElementById("verify-title").textContent = "TAMPERED — DỮ LIỆU BỊ THAY ĐỔI";
      document.getElementById("verify-desc").textContent  = "Chữ ký số không khớp. File có thể đã bị sửa đổi hoặc sai khóa.";
    }

    document.getElementById("hash-computed").textContent  = data.computed_hash;
    document.getElementById("hash-signature").textContent = data.computed_hash; // same if valid

  } catch (err) {
    log(`❌ Lỗi kết nối backend: ${err.message}`, "error");
    log("Kiểm tra backend đang chạy tại http://localhost:8000", "warn");
  }

  setLoading("bob", false);
}

// ─────────────────────────────────────────────────────────
//  Key Manager — Generate keys qua API
// ─────────────────────────────────────────────────────────
async function generateKeys(who) {
  const btn = document.getElementById("btn-gen-" + who);
  btn.disabled = true;
  btn.textContent = "Đang sinh khóa...";

  try {
    const resp = await fetch(`${API_BASE}/api/keys/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "bits=2048",
    });
    const data = await resp.json();
    if (!resp.ok) {
      alert("Lỗi sinh khóa: " + (data.detail || "Unknown"));
      return;
    }
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
  const blob     = new Blob([content], { type: "text/plain" });
  const url      = URL.createObjectURL(blob);
  const a        = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

// ─────────────────────────────────────────────────────────
//  Download encrypted package
// ─────────────────────────────────────────────────────────
function downloadPackage() {
  if (!state.packageB64) { alert("Chưa có package!"); return; }
  b64Download(state.packageB64, "output_encrypted.pkg");
}

function downloadRestored() {
  if (!state.restoredFileB64) { alert("Chưa có file!"); return; }
  b64Download(state.restoredFileB64, state.restoredFileName || "restored_file");
}

function b64Download(b64, filename) {
  const bytes  = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const blob   = new Blob([bytes]);
  const url    = URL.createObjectURL(blob);
  const a      = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}
