const crypto = require("crypto");

class WXBizMsgCrypt {
  constructor(token, encodingAESKey, corpId) {
    this.token = token;
    this.corpId = corpId;
    this.aesKey = Buffer.from(encodingAESKey + "=", "base64");
    this.iv = this.aesKey.slice(0, 16);
  }

  getSignature(timestamp, nonce, encrypt) {
    const arr = [this.token, timestamp, nonce, encrypt].sort();
    return crypto.createHash("sha1").update(arr.join("")).digest("hex");
  }

  decrypt(encrypted) {
    const decipher = crypto.createDecipheriv("aes-256-cbc", this.aesKey, this.iv);
    decipher.setAutoPadding(false);
    let decrypted = Buffer.concat([decipher.update(encrypted, "base64"), decipher.final()]);

    const padLen = decrypted[decrypted.length - 1];
    decrypted = decrypted.slice(0, decrypted.length - padLen);

    const msgLen = decrypted.readUInt32BE(16);
    const message = decrypted.slice(20, 20 + msgLen).toString("utf8");
    const corpId = decrypted.slice(20 + msgLen).toString("utf8");

    if (corpId !== this.corpId) {
      throw new Error("CorpID mismatch");
    }
    return message;
  }

  encrypt(text) {
    const random = crypto.randomBytes(16);
    const msgBuf = Buffer.from(text, "utf8");
    const msgLen = Buffer.alloc(4);
    msgLen.writeUInt32BE(msgBuf.length, 0);
    const corpBuf = Buffer.from(this.corpId, "utf8");

    let data = Buffer.concat([random, msgLen, msgBuf, corpBuf]);
    const padLen = 32 - (data.length % 32);
    data = Buffer.concat([data, Buffer.alloc(padLen, padLen)]);

    const cipher = crypto.createCipheriv("aes-256-cbc", this.aesKey, this.iv);
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(data), cipher.final()]).toString("base64");
  }

  verifyURL(msgSignature, timestamp, nonce, echostr) {
    const signature = this.getSignature(timestamp, nonce, echostr);
    if (signature !== msgSignature) {
      throw new Error("Signature verification failed");
    }
    return this.decrypt(echostr);
  }

  decryptMsg(msgSignature, timestamp, nonce, encrypted) {
    const signature = this.getSignature(timestamp, nonce, encrypted);
    if (signature !== msgSignature) {
      throw new Error("Signature verification failed");
    }
    return this.decrypt(encrypted);
  }
}

module.exports = WXBizMsgCrypt;
