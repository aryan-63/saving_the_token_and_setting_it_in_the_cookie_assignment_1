const { encrypt, decrypt } = require('./script');

// Encrypt a payload
const payload = { userId: 123, role: 'admin' };
const encryptedToken = encrypt(payload);
console.log('Encrypted Token:', encryptedToken);

// Decrypt the token
const decryptedPayload = decrypt(encryptedToken);
if (decryptedPayload) {
  console.log('Decrypted Payload:', decryptedPayload);
} else {
  console.log('Failed to decrypt the token');
}