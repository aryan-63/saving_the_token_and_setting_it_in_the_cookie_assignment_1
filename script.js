const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const SECRET_KEY = 'your_jwt_secret_key'; // Secret key for JWT signing
const ENCRYPTION_KEY = crypto.randomBytes(32); // 256-bit key for AES encryption
const IV = crypto.randomBytes(16); // Initialization vector for AES encryption

/**
 * Encrypt the payload and return the token
 * @param {Object} payload - The data to be included in the JWT token
 * @returns {string} - Encrypted token
 */
const encrypt = (payload) => {
  // Generate a JWT token
  const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '1h' });

  // Encrypt the JWT token using AES
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Return the encrypted token
  return encrypted;
};

/**
 * Decrypt the token and return the decoded payload
 * @param {string} token - The encrypted token
 * @returns {Object|null} - Decoded payload or null if decryption/verification fails
 */
const decrypt = (token) => {
  try {
    // Decrypt the encrypted token using AES
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
    let decrypted = decipher.update(token, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    // Verify the JWT token and decode the payload
    const decodedPayload = jwt.verify(decrypted, SECRET_KEY);
    return decodedPayload;
  } catch (error) {
    console.error('Decryption/Verification failed:', error.message);
    return null;
  }
};

module.exports = {
  encrypt,
  decrypt,
};