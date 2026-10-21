// Simple Web Crypto API utilities corresponding directly to the original Python program

// Convert string to Uint8Array (message.encode())
export function strToBuffer(str) {
  return new TextEncoder().encode(str);
}

// Convert Uint8Array to string (decrypted.decode())
export function bufferToStr(buf) {
  return new TextDecoder().decode(buf);
}

// Convert ArrayBuffer or Uint8Array to Hex string for easy display
export function bufferToHex(buf) {
  const byteArr = new Uint8Array(buf);
  return Array.from(byteArr)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

// 1. Generate RSA Keys (Sender: for RSA-PSS signing, Receiver: for RSA-OAEP encryption)
export async function generateRSAKeyPair(usageType) {
  if (usageType === 'sign') {
    // RSA-PSS for digital signatures (equivalent to padding.PSS in Python)
    return await window.crypto.subtle.generateKey(
      {
        name: 'RSA-PSS',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]), // 65537
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify']
    );
  } else {
    // RSA-OAEP for AES key encryption (equivalent to padding.OAEP in Python)
    return await window.crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]), // 65537
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt']
    );
  }
}

// 2. Compute SHA-256 hash (for educational visualization)
export async function computeSHA256(message) {
  const data = strToBuffer(message);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  return bufferToHex(hashBuffer);
}

// 3. Create Digital Signature using Sender Private Key (RSA-PSS + SHA-256)
export async function createSignature(message, privateKey) {
  const data = strToBuffer(message);
  const signatureBuffer = await window.crypto.subtle.sign(
    {
      name: 'RSA-PSS',
      saltLength: 32, // SHA-256 salt length
    },
    privateKey,
    data
  );
  return signatureBuffer;
}

// 4. Verify Digital Signature using Sender Public Key
export async function verifySignature(message, signatureBuffer, publicKey) {
  try {
    const data = strToBuffer(message);
    const isValid = await window.crypto.subtle.verify(
      {
        name: 'RSA-PSS',
        saltLength: 32,
      },
      publicKey,
      signatureBuffer,
      data
    );
    return isValid;
  } catch (e) {
    console.error('Signature verification error:', e);
    return false;
  }
}

// 5. Encrypt message using AES-256-GCM (Browser equivalent of Python AES-256)
export async function encryptMessageAES(message) {
  // Generate random 256-bit AES key
  const aesKey = await window.crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true, // exportable so we can encrypt it with RSA
    ['encrypt', 'decrypt']
  );

  // Generate random 96-bit (12 bytes) or 128-bit IV
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const data = strToBuffer(message);

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    aesKey,
    data
  );

  // Export raw AES key bytes to encrypt with receiver's RSA key
  const rawAesKey = await window.crypto.subtle.exportKey('raw', aesKey);

  return {
    rawAesKey,
    iv,
    encryptedBuffer,
  };
}

// 6. Encrypt AES key using Receiver's RSA Public Key (RSA-OAEP)
export async function encryptAESKeyWithRSA(rawAesKey, receiverPublicKey) {
  const encryptedKeyBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'RSA-OAEP',
    },
    receiverPublicKey,
    rawAesKey
  );
  return encryptedKeyBuffer;
}

// 7. Decrypt AES key using Receiver's RSA Private Key (RSA-OAEP)
export async function decryptAESKeyWithRSA(encryptedKeyBuffer, receiverPrivateKey) {
  const rawAesKey = await window.crypto.subtle.decrypt(
    {
      name: 'RSA-OAEP',
    },
    receiverPrivateKey,
    encryptedKeyBuffer
  );
  return rawAesKey;
}

// 8. Decrypt message using decrypted AES key
export async function decryptMessageAES(rawAesKey, iv, encryptedBuffer) {
  // Import the raw AES key back into a CryptoKey object
  const aesKey = await window.crypto.subtle.importKey(
    'raw',
    rawAesKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['decrypt']
  );

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    aesKey,
    encryptedBuffer
  );

  return bufferToStr(decryptedBuffer);
}
