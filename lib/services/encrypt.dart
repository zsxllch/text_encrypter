import 'dart:convert';
import 'dart:typed_data';

import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:archive/archive.dart';
import 'package:cryptography/cryptography.dart'; // Keep for hashing if needed, or remove if unused

/// Encrypts [plainText] using AES-256-CBC with key [keyBytes] and **Fixed IV**.
/// Supports smart compression (GZIP only if it reduces size).
///
/// Returns Base64 of the concatenation: "cipherText".
/// Inside cipherText (decrypted): "flag(1) | payload".
/// Flag: 0 = No Compression, 1 = GZIP Compression.
///
/// **IV Strategy**: IV is derived from the [keyBytes] itself (MD5 of key).
/// This removes IV from output, saving space, but makes encryption deterministic.
/// The shared [keyBytes] must be 32 bytes (256-bit).
Future<String> encryptText({
	required String plainText,
	required Uint8List keyBytes,
}) async {
	if (keyBytes.length != 32) {
		throw ArgumentError('keyBytes must be 32 bytes for AES-256');
	}

	final plainBytes = utf8.encode(plainText);
	
	// Attempt GZIP compression
	final compressedBytes = Uint8List.fromList(GZipEncoder().encode(plainBytes)!);

	// Smart Compression Decision
	// We add 1 byte flag.
	// If (1 + compressed) < (1 + plain), use compressed.
	// Otherwise use plain.
	// Actually, GZIP header/footer overhead is usually > 1 byte diff, so we check strictly.
	
	final bool useCompression = compressedBytes.length < plainBytes.length;
	
	final BytesBuilder payloadBuilder = BytesBuilder();
	if (useCompression) {
		payloadBuilder.addByte(1); // Flag: Compressed
		payloadBuilder.add(compressedBytes);
	} else {
		payloadBuilder.addByte(0); // Flag: Uncompressed
		payloadBuilder.add(plainBytes);
	}
	final finalPayload = payloadBuilder.toBytes();

	// Generate Fixed IV (16 bytes) from Key
	// We use MD5 of the keyBytes to get a deterministic 16-byte IV.
	// Note: Dart's crypto package has MD5. 'package:cryptography' has Sha256 etc.
	// Let's use simple truncation/XOR or Sha256 and truncate.
	// Since we already have 'package:cryptography', let's use SHA256(key) -> take first 16 bytes.
	final hash = await Sha256().hash(keyBytes);
	final ivBytes = Uint8List.fromList(hash.bytes.sublist(0, 16));
	final iv = encrypt.IV(ivBytes);

	final key = encrypt.Key(keyBytes);

	final encrypter = encrypt.Encrypter(encrypt.AES(key, mode: encrypt.AESMode.cbc));
	final encrypted = encrypter.encryptBytes(finalPayload, iv: iv);

	// Output format: cipherText only (IV is implied)
	return base64Encode(encrypted.bytes);
}


