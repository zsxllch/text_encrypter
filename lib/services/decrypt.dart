import 'dart:convert';
import 'dart:typed_data';

import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:archive/archive.dart';
import 'package:cryptography/cryptography.dart';

/// Decrypts Base64 [cipherTextB64] produced by encrypt.dart.
/// Supports smart compression (flag byte).
/// Uses **Fixed IV** derived from [keyBytes].
///
/// Input layout (bytes after Base64 decode):
///   cipherText (IV is not included)
/// Decrypted payload: flag(1) | content
/// The shared [keyBytes] must be 32 bytes (256-bit).
Future<String> decryptText({
	required String cipherTextB64,
	required Uint8List keyBytes,
}) async {
	final data = base64Decode(cipherTextB64);
	// In AES-CBC with padding, minimum size is 1 block (16 bytes).
	if (data.length < 16) {
		throw ArgumentError('cipher too short');
	}

	if (keyBytes.length != 32) {
		throw ArgumentError('keyBytes must be 32 bytes for AES-256');
	}

	// Derive Fixed IV from Key
	final hash = await Sha256().hash(keyBytes);
	final ivBytes = Uint8List.fromList(hash.bytes.sublist(0, 16));
	final iv = encrypt.IV(ivBytes);

	final key = encrypt.Key(keyBytes);
	final encrypter = encrypt.Encrypter(encrypt.AES(key, mode: encrypt.AESMode.cbc));
	final cipherBytes = encrypt.Encrypted(data);

	try {
		final decryptedBytes = encrypter.decryptBytes(cipherBytes, iv: iv);
		
		if (decryptedBytes.isEmpty) return '';

		// Check compression flag
		// New format has 1 byte flag at start.
		
		final flag = decryptedBytes[0];
		final content = decryptedBytes.sublist(1);
		
		if (flag == 1) {
			// GZIP Compressed
			try {
				final plainBytes = GZipDecoder().decodeBytes(content);
				return utf8.decode(plainBytes);
			} catch (e) {
				throw FormatException('Decompression failed: $e');
			}
		} else if (flag == 0) {
			// Uncompressed
			return utf8.decode(content);
		} else {
			// Unknown flag.
			// Legacy fallback logic is removed because format has changed drastically (IV removed).
			// If we can't parse flag, it's likely wrong key or corrupted data.
			return utf8.decode(decryptedBytes);
		}

	} catch (e) {
		// AES-CBC decryption failure (padding error usually)
		throw FormatException('Decryption failed: $e');
	}
}


