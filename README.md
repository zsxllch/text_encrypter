# text_encrypter

双重加密文本工具：AES-256-GCM → ChaCha20-Poly1305

## 使用方式

1. 输入明文（或粘贴 Base64 密文用于解密）
2. 输入口令（留空将使用内置默认口令）
3. 选择模式：加密或解密
4. 点击按钮执行，结果显示在输出框，可复制

## 加密/解密流程

- 加密：原文 → AES-256-GCM(K, IV1=随机12B) → 中间密文 → ChaCha20-Poly1305(K, nonce=随机12B) → 最终密文
- 解密：最终密文 → ChaCha20-Poly1305(K, nonce) → 中间密文 → AES-256-GCM(K, IV1) → 原文

## 密钥与输出格式

- 口令派生：`key = SHA-256(UTF8(passphrase))`，得到 32 字节作为 AES-256 与 ChaCha20 的共享密钥
- 输出为 Base64，内部按字节拼接：
  - `iv(12) | nonce(12) | chachaCipher | aesTag(16) | chachaTag(16)`
  - 其中 `aesTag` 是 AES-GCM 的认证标签，`chachaTag` 是 ChaCha20-Poly1305 的认证标签

注意：要解密，需使用相同口令；密文需是上述格式的 Base64 字符串。
