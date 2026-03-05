import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
// Pure Dart implementation (no platform plugin)

/// Decrypts Base64 [cipherTextB64] produced by encrypt.dart.
/// Input layout (bytes after Base64 decode):
///   iv(12) | nonce(12) | chachaCipher | aesTag(16) | chachaTag(16)
/// The shared [keyBytes] must be 32 bytes (256-bit).
Future<String> decryptText({
	required String cipherTextB64,
	required Uint8List keyBytes,
}) async {
	final data = base64Decode(cipherTextB64);
	if (data.length < 12 + 12 + 16 + 16) {
		throw ArgumentError('cipher too short');
	}
	final iv = Uint8List.view(data.buffer, 0, 12);
	final nonce = Uint8List.view(data.buffer, 12, 12);
	final chachaTag = Uint8List.view(data.buffer, data.length - 16, 16);
	final aesTag = Uint8List.view(data.buffer, data.length - 32, 16);
	final chachaCipher = Uint8List.view(data.buffer, 24, data.length - 24 - 32);

	if (keyBytes.length != 32) {
		throw ArgumentError('keyBytes must be 32 bytes for AES-256/ChaCha20');
	}

	final aesGcm = AesGcm.with256bits();
	final chacha = Chacha20.poly1305Aead();

	// Stage 1: ChaCha20-Poly1305 decrypt to get AES ciphertext
	final chachaSecretKey = SecretKey(keyBytes);
	final chachaBox = SecretBox(
		chachaCipher,
		nonce: nonce,
		mac: Mac(chachaTag),
	);
	final aesCipher = await chacha.decrypt(
		chachaBox,
		secretKey: chachaSecretKey,
	);

	// Stage 2: AES-256-GCM decrypt to get plaintext
	final aesSecretKey = SecretKey(keyBytes);
	final aesBox = SecretBox(
		aesCipher,
		nonce: iv,
		mac: Mac(aesTag),
	);
	final plainBytes = await aesGcm.decrypt(
		aesBox,
		secretKey: aesSecretKey,
	);
	return utf8.decode(plainBytes);
}


