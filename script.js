import jwt from "jsonwebtoken"
import CryptoJS from "crypto-js";
const encrypt = (payload, secret) => {
  // your code here and return token
  const token=jwt.sign(payload,secret,{expiresIn:'1h'})
  const encryptedToken=CryptoJS.AES.encrypt(token,secret).toString()
  return encryptedToken
};

const decrypt = (encryptedToken, secret) => {
  try {
    const bytes = CryptoJS.AES.decrypt(encryptedToken, secret);
    const decryptedToken = bytes.toString(CryptoJS.enc.Utf8);

    const decodedPayload = jwt.verify(decryptedToken, secret);

    return decodedPayload;
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      throw new Error("Token has expired");
    }
    throw new Error("Invalid token or decryption failed");
  }
};

module.exports = { encrypt, decrypt };
