## [在线访问](https://zsxllch.github.io/text_encrypter/)

文本加密工具：AES-256-CBC

## 使用方式

1. 输入明文（或粘贴 Base64 密文用于解密）
2. 输入口令（留空将使用内置默认口令）
3. 选择模式：加密或解密
4. 点击按钮执行，结果显示在输出框，可复制

## 加密/解密流程

- 加密：原文 → 智能压缩(GZIP/直通 + 1字节标志) → AES-256-CBC(K, IV=Fixed) → Base64
- 解密：Base64 → AES-256-CBC(K, IV=Fixed) → 检查标志位 → (GZIP解压/直通) → 原文

## 密钥与输出格式

- 口令派生：`key = SHA-256(UTF8(passphrase))`，得到 32 字节 AES 密钥
- **固定 IV**：`IV = SHA-256(key)[0..16]` (取前16字节)。
  - 注意：使用固定 IV 会导致加密具有确定性（相同原文+相同口令=相同密文）。
- 输出为 Base64，内部为纯密文（IV 不包含在输出中）：
  - `cipherText`
  - 密文对应明文结构：`flag(1) | payload`
    - `flag=1`: GZIP压缩
    - `flag=0`: 无压缩
  - 使用 PKCS7 填充

注意：要解密，需使用相同口令；密文需是上述格式的 Base64 字符串。
