/**
 * @param {number} bytesCount
 */
export const generateRandomBase64String = (bytesCount) => {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(bytesCount));

  return btoa(String.fromCharCode(...bytes));
};

export const generateSalt = () => {
  return generateRandomBase64String(24);
};

export const generateNonce = () => {
  return generateRandomBase64String(24);
};

/**
 *  @param {string} password
 *  @param {string} salt
 *  @param {number} iterations
 */
export const generateSaltedPassword = async (password, salt, iterations) => {
  const keyMaterial = await globalThis.crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password).buffer,
    "PBKDF2",
    false,
    ["deriveBits"],
  );

  const saltedPassword = await globalThis.crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(salt).buffer,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    256,
  );

  return new Uint8Array(saltedPassword);
};

/**
 * @param {ArrayBuffer} saltedPassword
 */
export const generateClientKey = async (saltedPassword) => {
  const hmacKey = await globalThis.crypto.subtle.importKey(
    "raw",
    saltedPassword,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const clientKey = await globalThis.crypto.subtle.sign(
    "HMAC",
    hmacKey,
    new TextEncoder().encode("Client Key"),
  );

  return new Uint8Array(clientKey);
};

/**
 * @param {Uint8Aray} clientKey
 */
export const generateStoredKey = async (clientKey) => {
  const storedKey = await globalThis.crypto.subtle.digest(
    "SHA-256",
    clientKey,
  );

  return new Uint8Array(storedKey);
};

/**
 * @param {ArrayBuffer} saltedPassword
 */
export const generateServerKey = async (saltedPassword) => {
  const hmacKey = await globalThis.crypto.subtle.importKey(
    "raw",
    saltedPassword,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const clientKey = await globalThis.crypto.subtle.sign(
    "HMAC",
    hmacKey,
    new TextEncoder().encode("Server Key"),
  );

  return new Uint8Array(clientKey);
};

/**
 * @param {string} email
 * @param {string} nonce
 * @param {string} salt
 * @param {number} iterations
 */
export const generateAuthMessage = (email, nonce, salt, iterations) => {
  return `${email},${nonce},${salt},${iterations},${nonce}`;
};

/**
 * @param {Uint8Array} key
 * @param {string} authMessage
 */
export const generateSignature = async (key, authMessage) => {
  const hmacKey = await globalThis.crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const clientSignature = await globalThis.crypto.subtle.sign(
    "HMAC",
    hmacKey,
    new TextEncoder().encode(authMessage),
  );

  return new Uint8Array(clientSignature);
};

/**
 * @param {Uint8Array} left
 * @param {Uint8Array} right
 */
export const xorUint8Arrays = (left, right) => {
  if (left.length !== right.length)
    throw new Error("invalid array length");

  return left.map((curr, i) => {
    return curr ^ right[i];
  });
};
