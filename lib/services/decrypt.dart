import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:archive/archive.dart';

/// Decrypts Base64 [cipherTextB64] produced by encrypt.dart.
/// The decrypted bytes are then decompressed using GZIP.
///
/// Input layout (bytes after Base64 decode):
///   iv(12) | cipherText | mac(16)
/// The shared [keyBytes] must be 32 bytes (256-bit).
Future<String> decryptText({
	required String cipherTextB64,
	required Uint8List keyBytes,
}) async {
	final data = base64Decode(cipherTextB64);
	if (data.length < 12 + 16) {
		throw ArgumentError('cipher too short');
	}
	final iv = Uint8List.view(data.buffer, 0, 12);
	final aesTag = Uint8List.view(data.buffer, data.length - 16, 16);
	final aesCipher = Uint8List.view(data.buffer, 12, data.length - 12 - 16);

	if (keyBytes.length != 32) {
		throw ArgumentError('keyBytes must be 32 bytes for AES-256');
	}

	final aesGcm = AesGcm.with256bits();

	// AES-256-GCM decrypt to get compressed bytes
	final aesSecretKey = SecretKey(keyBytes);
	final aesBox = SecretBox(
		aesCipher,
		nonce: iv,
		mac: Mac(aesTag),
	);
	final compressedBytes = await aesGcm.decrypt(
		aesBox,
		secretKey: aesSecretKey,
	);

	// Decompress GZIP
	try {
		final plainBytes = GZipDecoder().decodeBytes(compressedBytes);
		return utf8.decode(plainBytes);
	} catch (e) {
		// Fallback for backward compatibility (if not compressed)
		// Or if data is just not valid GZIP
		try {
			return utf8.decode(compressedBytes);
		} catch (_) {
			rethrow; // Rethrow original GZIP error if fallback also fails
		}
	}
}


