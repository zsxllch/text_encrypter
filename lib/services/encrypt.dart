import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
// Pure Dart implementation (no platform plugin)

/// Encrypts [plainText] using a two-stage scheme:
/// 1) AES-256-GCM with key [keyBytes] and random 12-byte IV
/// 2) ChaCha20-Poly1305 with the same key and random 12-byte nonce
///
/// Returns Base64 of the concatenation: "iv(12) | nonce(12) | chachaCipher | aesTag(16) | chachaTag(16)".
/// The shared [keyBytes] must be 32 bytes (256-bit).
Future<String> encryptText({
	required String plainText,
	required Uint8List keyBytes,
}) async {
	final aesGcm = AesGcm.with256bits();
	final chacha = Chacha20.poly1305Aead();

	if (keyBytes.length != 32) {
		throw ArgumentError('keyBytes must be 32 bytes for AES-256/ChaCha20');
	}

	// Random IV/nonce
	final iv = aesGcm.newNonce(); // 12 bytes
	final nonce = chacha.newNonce(); // 12 bytes

	// Stage 1: AES-256-GCM
	final aesSecretKey = SecretKey(keyBytes);
	final aesSecretBox = await aesGcm.encrypt(
		utf8.encode(plainText),
		secretKey: aesSecretKey,
		nonce: iv,
	);

	// Stage 2: ChaCha20-Poly1305 over AES ciphertext
	final chachaSecretKey = SecretKey(keyBytes);
	final chachaSecretBox = await chacha.encrypt(
		aesSecretBox.cipherText,
		secretKey: chachaSecretKey,
		nonce: nonce,
	);

	// Output format: iv(12) | nonce(12) | chachaCipher | aesTag(16) | chachaTag(16)
	final builder = BytesBuilder();
	builder.add(iv);
	builder.add(nonce);
	builder.add(chachaSecretBox.cipherText);
	builder.add(aesSecretBox.mac.bytes);
	builder.add(chachaSecretBox.mac.bytes);
	final combined = builder.toBytes();
	return base64Encode(combined);
}


