/**
 * Simulated E2E encryption using Web Crypto API.
 * In production, keys would be exchanged via a key server.
 */

let keyPair = null;

async function getKeyPair() {
  if (keyPair) return keyPair;
  keyPair = await window.crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt']
  );
  return keyPair;
}

export async function encryptMessage(plaintext) {
  try {
    const { publicKey } = await getKeyPair();
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    const encrypted = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, data);
    return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
  } catch {
    // Fallback: return base64 encoded (simulated encryption for demo)
    return btoa(unescape(encodeURIComponent(plaintext)));
  }
}

export async function decryptMessage(ciphertext) {
  try {
    const { privateKey } = await getKeyPair();
    const data = Uint8Array.from(atob(ciphertext), (c) => c.charCodeAt(0));
    const decrypted = await window.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, data);
    return new TextDecoder().decode(decrypted);
  } catch {
    // Fallback: decode base64
    try {
      return decodeURIComponent(escape(atob(ciphertext)));
    } catch {
      return '[Encrypted message]';
    }
  }
}

export function generateMessageId() {
  return crypto.randomUUID ? crypto.randomUUID() : `msg-${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
}
