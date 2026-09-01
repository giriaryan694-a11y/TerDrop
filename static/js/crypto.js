/**
 * TerDrop Client-Side Crypto
 * Hybrid encryption: AES-256-GCM (file) + RSA-OAEP (key wrapping).
 *
 * Flow:
 *   1. Fetch server's RSA public key (PEM) from /api/public-key
 *   2. Generate a random AES-256-GCM key locally (per file)
 *   3. Encrypt the file bytes with that AES key + random 12-byte IV
 *   4. Wrap (RSA-OAEP encrypt) the AES key with the server's public key
 *   5. Upload: ciphertext blob + base64(iv) + base64(wrapped_key)
 *
 * The server NEVER sees the plaintext file or the AES key in transit —
 * only the admin holding the RSA private key can unwrap and decrypt.
 * Cloudflare and any network intermediary only see ciphertext.
 */

const TerDropCrypto = (() => {

  let cachedPublicKey = null;   // CryptoKey (imported)
  let cachedPublicKeyPem = null;

  async function fetchPublicKey() {
    if (cachedPublicKey) return cachedPublicKey;

    const res = await fetch("/api/public-key");
    if (!res.ok) throw new Error("Could not fetch server public key");
    const data = await res.json();
    cachedPublicKeyPem = data.public_key_pem;

    const key = await importRsaPublicKey(cachedPublicKeyPem);
    cachedPublicKey = key;
    return key;
  }

  function pemToArrayBuffer(pem) {
    const b64 = pem
      .replace(/-----BEGIN PUBLIC KEY-----/, "")
      .replace(/-----END PUBLIC KEY-----/, "")
      .replace(/\s+/g, "");
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  async function importRsaPublicKey(pem) {
    const der = pemToArrayBuffer(pem);
    return crypto.subtle.importKey(
      "spki",
      der,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["encrypt"]
    );
  }

  function bufToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  }

  /**
   * Encrypt a File/Blob for upload.
   * Returns { ciphertextBlob, ivB64, wrappedKeyB64 }
   */
  async function encryptFile(file, onProgress) {
    const publicKey = await fetchPublicKey();

    // 1. Generate random AES-256-GCM key
    const aesKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    // 2. Read file into memory (fine for files under a few hundred MB on mobile)
    const fileBuffer = await file.arrayBuffer();
    if (onProgress) onProgress(30);

    // 3. Encrypt with AES-GCM
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      aesKey,
      fileBuffer
    );
    if (onProgress) onProgress(65);

    // 4. Export raw AES key, then wrap it with RSA-OAEP
    const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
    const wrappedKey = await crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      rawAesKey
    );
    if (onProgress) onProgress(80);

    return {
      ciphertextBlob: new Blob([ciphertext], { type: "application/octet-stream" }),
      ivB64: bufToBase64(iv.buffer),
      wrappedKeyB64: bufToBase64(wrappedKey),
      plaintextSize: file.size,
    };
  }

  /** Check browser support before attempting encryption. */
  function isSupported() {
    return !!(window.crypto && window.crypto.subtle);
  }

  return { encryptFile, fetchPublicKey, isSupported };
})();
