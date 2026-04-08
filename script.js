// ---------- Storage and crypto constants ----------
const STORAGE_KEY = "cyberlock_vault_v1";
const ITERATIONS = 250000;
const KEY_LENGTH = 256;

// ---------- App state ----------
let encryptionKey = null;
let entries = [];
let isFirstSetup = false;

// ---------- DOM references ----------
const loginSection = document.getElementById("login-section");
const appSection = document.getElementById("app-section");
const loginTitle = document.getElementById("login-title");
const loginSubtitle = document.getElementById("login-subtitle");
const loginForm = document.getElementById("login-form");
const masterPasswordInput = document.getElementById("master-password");
const masterPasswordConfirmInput = document.getElementById("master-password-confirm");
const confirmWrap = document.getElementById("confirm-wrap");
const toggleMasterBtn = document.getElementById("toggle-master");
const lockBtn = document.getElementById("lock-btn");

const entryForm = document.getElementById("entry-form");
const entryIdInput = document.getElementById("entry-id");
const websiteInput = document.getElementById("website");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");
const toggleEntryPasswordBtn = document.getElementById("toggle-entry-password");
const cancelEditBtn = document.getElementById("cancel-edit");
const entriesList = document.getElementById("entries-list");
const searchInput = document.getElementById("search-input");
const strengthBar = document.getElementById("strength-bar");
const strengthLabel = document.getElementById("strength-label");

const genLengthInput = document.getElementById("gen-length");
const genUppercaseInput = document.getElementById("gen-uppercase");
const genNumbersInput = document.getElementById("gen-numbers");
const genSymbolsInput = document.getElementById("gen-symbols");
const generatedPasswordInput = document.getElementById("generated-password");
const generateBtn = document.getElementById("generate-btn");
const useGeneratedBtn = document.getElementById("use-generated-btn");

const toast = document.getElementById("toast");

// ---------- Utility helpers ----------
function showToast(message, type = "success") {
  toast.textContent = message;
  toast.className = `toast show ${type}`;
  clearTimeout(showToast.timeoutId);
  showToast.timeoutId = setTimeout(() => {
    toast.className = "toast";
  }, 2500);
}

function toBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function fromBase64(base64) {
  return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
}

function generateId() {
  return crypto.randomUUID();
}

function secureRandomChar(charset) {
  const random = new Uint32Array(1);
  crypto.getRandomValues(random);
  return charset[random[0] % charset.length];
}

// ---------- Crypto layer ----------
async function sha256Text(text) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return new Uint8Array(hashBuffer);
}

async function deriveAesKeyFromMaster(masterPassword, saltBytes) {
  // Requirement: hash master password first, then derive a symmetric key.
  const hashedMaster = await sha256Text(masterPassword);
  const baseKey = await crypto.subtle.importKey("raw", hashedMaster, "PBKDF2", false, ["deriveKey"]);

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations: ITERATIONS,
    },
    baseKey,
    { name: "AES-GCM", length: KEY_LENGTH },
    false,
    ["encrypt", "decrypt"]
  );
}

async function deriveVerifier(masterPassword, saltBytes) {
  // Store only a deterministic verifier, never the plaintext master password.
  const hashedMaster = await sha256Text(masterPassword);
  const baseKey = await crypto.subtle.importKey("raw", hashedMaster, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations: ITERATIONS,
    },
    baseKey,
    256
  );
  return toBase64(bits);
}

async function encryptVaultData(data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(data));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, plaintext);
  return { iv: toBase64(iv), ciphertext: toBase64(ciphertext) };
}

async function decryptVaultData(vault) {
  const iv = fromBase64(vault.iv);
  const ciphertext = fromBase64(vault.ciphertext);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, encryptionKey, ciphertext);
  return JSON.parse(new TextDecoder().decode(plaintext));
}

// ---------- Persistence ----------
function loadStoredData() {
  const raw = localStorage.getItem(STORAGE_KEY);
  return raw ? JSON.parse(raw) : null;
}

function saveStoredData(payload) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
}

async function saveEntriesEncrypted() {
  const stored = loadStoredData();
  const vault = await encryptVaultData(entries);
  saveStoredData({
    master: stored.master,
    vault,
  });
}

// ---------- Login / setup flow ----------
function updateLoginMode() {
  const stored = loadStoredData();
  isFirstSetup = !stored || !stored.master || !stored.vault;

  if (isFirstSetup) {
    loginTitle.textContent = "Create Master Password";
    loginSubtitle.textContent = "Set a strong master password to protect your vault.";
    confirmWrap.classList.remove("hidden");
    masterPasswordConfirmInput.required = true;
  } else {
    loginTitle.textContent = "Unlock Vault";
    loginSubtitle.textContent = "Enter your master password.";
    confirmWrap.classList.add("hidden");
    masterPasswordConfirmInput.required = false;
  }
}

async function handleFirstSetup(masterPassword) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const verifier = await deriveVerifier(masterPassword, salt);
  encryptionKey = await deriveAesKeyFromMaster(masterPassword, salt);
  entries = [];
  const vault = await encryptVaultData(entries);
  saveStoredData({
    master: {
      salt: toBase64(salt),
      verifier,
    },
    vault,
  });
}

async function handleUnlock(masterPassword) {
  const stored = loadStoredData();
  const salt = fromBase64(stored.master.salt);
  const inputVerifier = await deriveVerifier(masterPassword, salt);

  if (inputVerifier !== stored.master.verifier) {
    throw new Error("Invalid master password");
  }

  encryptionKey = await deriveAesKeyFromMaster(masterPassword, salt);
  entries = await decryptVaultData(stored.vault);
}

function lockVault() {
  encryptionKey = null;
  entries = [];
  loginSection.classList.remove("hidden");
  appSection.classList.add("hidden");
  masterPasswordInput.value = "";
  masterPasswordConfirmInput.value = "";
  showToast("Vault locked", "warning");
}

// ---------- Password strength ----------
function evaluatePasswordStrength(password) {
  if (!password) return { score: 0, label: "Weak", color: "#ef4444" };

  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSymbol = /[^A-Za-z0-9]/.test(password);
  const variety = [hasLower, hasUpper, hasNumber, hasSymbol].filter(Boolean).length;
  const score = Math.min(4, Math.floor(password.length / 4) + variety - 1);

  if (score <= 1) return { score, label: "Weak", color: "#ef4444" };
  if (score <= 2) return { score, label: "Medium", color: "#f59e0b" };
  return { score, label: "Strong", color: "#22c55e" };
}

function renderStrength(password) {
  const { score, label, color } = evaluatePasswordStrength(password);
  const width = `${Math.max(15, (score / 4) * 100)}%`;
  strengthBar.style.width = width;
  strengthBar.style.background = color;
  strengthLabel.textContent = label;
}

// ---------- Entry rendering ----------
function renderEntries() {
  const q = searchInput.value.trim().toLowerCase();
  const filtered = entries.filter(
    (entry) =>
      entry.website.toLowerCase().includes(q) ||
      entry.username.toLowerCase().includes(q)
  );

  if (!filtered.length) {
    entriesList.innerHTML = `<p class="entry-meta">No entries found.</p>`;
    return;
  }

  entriesList.innerHTML = filtered
    .map(
      (entry) => `
      <article class="entry-card" data-id="${entry.id}">
        <div class="entry-top">
          <strong>${escapeHtml(entry.website)}</strong>
          <small>${new Date(entry.updatedAt).toLocaleString()}</small>
        </div>
        <div class="entry-meta">Username: ${escapeHtml(entry.username)}</div>
        <div class="entry-password" data-password>${maskPassword(entry.password)}</div>
        <div class="entry-actions">
          <button data-action="toggle">Show</button>
          <button data-action="copy">Copy</button>
          <button data-action="edit">Edit</button>
          <button data-action="delete" class="danger-btn">Delete</button>
        </div>
      </article>
    `
    )
    .join("");
}

function maskPassword(password) {
  return "•".repeat(Math.max(8, password.length));
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value;
  return div.innerHTML;
}

function resetEntryForm() {
  entryForm.reset();
  entryIdInput.value = "";
  cancelEditBtn.classList.add("hidden");
  renderStrength("");
}

async function upsertEntry() {
  const website = websiteInput.value.trim();
  const username = usernameInput.value.trim();
  const password = passwordInput.value;

  if (!website || !username || !password) {
    showToast("Please fill all fields", "error");
    return;
  }

  const existingId = entryIdInput.value;
  const now = Date.now();
  if (existingId) {
    entries = entries.map((item) =>
      item.id === existingId ? { ...item, website, username, password, updatedAt: now } : item
    );
    showToast("Entry updated");
  } else {
    entries.unshift({
      id: generateId(),
      website,
      username,
      password,
      updatedAt: now,
    });
    showToast("Entry saved");
  }

  await saveEntriesEncrypted();
  resetEntryForm();
  renderEntries();
}

function startEditing(id) {
  const entry = entries.find((item) => item.id === id);
  if (!entry) return;
  entryIdInput.value = entry.id;
  websiteInput.value = entry.website;
  usernameInput.value = entry.username;
  passwordInput.value = entry.password;
  cancelEditBtn.classList.remove("hidden");
  renderStrength(passwordInput.value);
}

async function deleteEntry(id) {
  entries = entries.filter((entry) => entry.id !== id);
  await saveEntriesEncrypted();
  renderEntries();
  showToast("Entry deleted", "warning");
}

// ---------- Password generator ----------
function generatePassword() {
  const length = Math.min(64, Math.max(8, Number(genLengthInput.value) || 16));
  const includeUpper = genUppercaseInput.checked;
  const includeNumbers = genNumbersInput.checked;
  const includeSymbols = genSymbolsInput.checked;

  let charset = "abcdefghijklmnopqrstuvwxyz";
  if (includeUpper) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (includeNumbers) charset += "0123456789";
  if (includeSymbols) charset += "!@#$%^&*()_+-=[]{}|;:,.<>?";

  if (!charset.length) {
    showToast("Choose at least one character option", "error");
    return "";
  }

  let result = "";
  for (let i = 0; i < length; i += 1) {
    result += secureRandomChar(charset);
  }
  generatedPasswordInput.value = result;
  return result;
}

// ---------- Event wiring ----------
toggleMasterBtn.addEventListener("click", () => {
  const isHidden = masterPasswordInput.type === "password";
  masterPasswordInput.type = isHidden ? "text" : "password";
  toggleMasterBtn.textContent = isHidden ? "Hide" : "Show";
});

toggleEntryPasswordBtn.addEventListener("click", () => {
  const isHidden = passwordInput.type === "password";
  passwordInput.type = isHidden ? "text" : "password";
  toggleEntryPasswordBtn.textContent = isHidden ? "Hide" : "Show";
});

lockBtn.addEventListener("click", lockVault);

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const master = masterPasswordInput.value;

  try {
    if (isFirstSetup) {
      if (master !== masterPasswordConfirmInput.value) {
        showToast("Passwords do not match", "error");
        return;
      }
      await handleFirstSetup(master);
      showToast("Master password created");
    } else {
      await handleUnlock(master);
      showToast("Vault unlocked");
    }

    loginSection.classList.add("hidden");
    appSection.classList.remove("hidden");
    masterPasswordInput.value = "";
    masterPasswordConfirmInput.value = "";
    renderEntries();
  } catch (error) {
    showToast(error.message || "Failed to unlock vault", "error");
  }
});

entryForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await upsertEntry();
});

cancelEditBtn.addEventListener("click", () => {
  resetEntryForm();
});

passwordInput.addEventListener("input", () => {
  renderStrength(passwordInput.value);
});

searchInput.addEventListener("input", renderEntries);

entriesList.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;

  const card = event.target.closest(".entry-card");
  if (!card) return;

  const entryId = card.dataset.id;
  const action = button.dataset.action;
  const entry = entries.find((item) => item.id === entryId);
  if (!entry) return;

  if (action === "toggle") {
    const passwordEl = card.querySelector("[data-password]");
    const showing = button.textContent === "Hide";
    passwordEl.textContent = showing ? maskPassword(entry.password) : entry.password;
    button.textContent = showing ? "Show" : "Hide";
  }

  if (action === "copy") {
    try {
      await navigator.clipboard.writeText(entry.password);
      showToast("Password copied");
    } catch {
      showToast("Clipboard access failed", "error");
    }
  }

  if (action === "edit") {
    startEditing(entryId);
  }

  if (action === "delete") {
    await deleteEntry(entryId);
  }
});

generateBtn.addEventListener("click", () => {
  const generated = generatePassword();
  if (generated) {
    showToast("Password generated");
  }
});

useGeneratedBtn.addEventListener("click", () => {
  if (!generatedPasswordInput.value) {
    const generated = generatePassword();
    if (!generated) return;
  }
  passwordInput.value = generatedPasswordInput.value;
  renderStrength(passwordInput.value);
  showToast("Generated password applied");
});

// ---------- Startup ----------
function init() {
  updateLoginMode();
  renderStrength("");
  generatePassword();
}

init();
