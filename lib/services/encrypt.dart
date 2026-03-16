import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:archive/archive.dart';

/// Encrypts [plainText] using AES-256-GCM with key [keyBytes] and random 12-byte IV.
/// The plainText is first compressed using GZIP to reduce size.
///
/// Returns Base64 of the concatenation: "iv(12) | cipherText | mac(16)".
/// The shared [keyBytes] must be 32 bytes (256-bit).
Future<String> encryptText({
	required String plainText,
	required Uint8List keyBytes,
}) async {
	final aesGcm = AesGcm.with256bits();

	if (keyBytes.length != 32) {
		throw ArgumentError('keyBytes must be 32 bytes for AES-256');
	}

	// Random IV/nonce
	final iv = aesGcm.newNonce(); // 12 bytes

	// Compress plaintext using GZIP
	final plainBytes = utf8.encode(plainText);
	// archive package returns List<int>, need to convert to Uint8List for AES
	final compressedBytes = Uint8List.fromList(GZipEncoder().encode(plainBytes)!);

	// AES-256-GCM
	final aesSecretKey = SecretKey(keyBytes);
	final aesSecretBox = await aesGcm.encrypt(
		compressedBytes,
		secretKey: aesSecretKey,
		nonce: iv,
	);

	// Output format: iv(12) | cipherText | mac(16)
	final builder = BytesBuilder();
	builder.add(iv);
	builder.add(aesSecretBox.cipherText);
	builder.add(aesSecretBox.mac.bytes);
	final combined = builder.toBytes();
	return base64Encode(combined);
}


