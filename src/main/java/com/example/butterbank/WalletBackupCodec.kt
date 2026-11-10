package com.example.butterbank

import android.util.Base64
import org.bouncycastle.crypto.generators.SCrypt
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class WalletMaterial(
    val privateSeed: ByteArray,
    val publicKey: String
)

object WalletBackupCodec {
    private const val VERSION = 2
    private const val SCRYPT_N = 1 shl 15
    private const val SCRYPT_R = 8
    private const val SCRYPT_P = 1
    private const val SALT_BYTES = 16
    private const val NONCE_BYTES = 12
    private const val KEY_BYTES = 32
    private const val TAG_BITS = 128
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val AAD_PREFIX = "butter-bank-wallet-v2:"

    fun generate(random: SecureRandom = SecureRandom()): WalletMaterial {
        val privateKey = Ed25519PrivateKeyParameters(random)
        return WalletMaterial(privateKey.encoded, privateKey.generatePublicKey().encoded.toHex())
    }

    fun publicKey(seed: ByteArray): String {
        require(seed.size == 32) { "Ed25519 private seed must be 32 bytes" }
        return Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded.toHex()
    }

    fun sign(seed: ByteArray, message: ByteArray): ByteArray {
        require(seed.size == 32) { "Ed25519 private seed must be 32 bytes" }
        val signer = org.bouncycastle.crypto.signers.Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(seed, 0))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    fun export(material: WalletMaterial, passphrase: String): String {
        require(passphrase.length >= 12) { "Wallet backup passphrase must contain at least 12 characters" }
        require(material.privateSeed.size == 32) { "Ed25519 private seed must be 32 bytes" }
        val public = publicKey(material.privateSeed)
        require(public == material.publicKey.lowercase()) { "Wallet public key does not match its private key" }
        val salt = ByteArray(SALT_BYTES).also { SecureRandom().nextBytes(it) }
        val nonce = ByteArray(NONCE_BYTES).also { SecureRandom().nextBytes(it) }
        val key = deriveKey(passphrase, salt)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
        cipher.updateAAD((AAD_PREFIX + public).toByteArray(StandardCharsets.US_ASCII))
        val ciphertext = cipher.doFinal(material.privateSeed)
        return JSONObject().apply {
            put("version", VERSION)
            put("kdf", "scrypt")
            put("cipher", "AES-256-GCM")
            put("salt", Base64.encodeToString(salt, Base64.NO_WRAP))
            put("nonce", Base64.encodeToString(nonce, Base64.NO_WRAP))
            put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            put("public_key", public)
        }.toString()
    }

    fun import(backup: String, passphrase: String): WalletMaterial {
        require(passphrase.length >= 12) { "Wallet backup passphrase must contain at least 12 characters" }
        require(backup.toByteArray(StandardCharsets.UTF_8).size <= 1_000_000) {
            "Wallet backup exceeds the 1 MB limit"
        }
        val json = JSONObject(backup)
        require(json.getInt("version") == VERSION) { "Unsupported wallet backup version" }
        require(json.getString("kdf") == "scrypt" && json.getString("cipher") == "AES-256-GCM") {
            "Unsupported wallet backup encryption"
        }
        val public = json.getString("public_key").lowercase()
        require(public.matches(Regex("^[0-9a-f]{64}$"))) { "Wallet public key is malformed" }
        val salt = Base64.decode(json.getString("salt"), Base64.NO_WRAP)
        val nonce = Base64.decode(json.getString("nonce"), Base64.NO_WRAP)
        val ciphertext = Base64.decode(json.getString("ciphertext"), Base64.NO_WRAP)
        require(salt.size == SALT_BYTES && nonce.size == NONCE_BYTES && ciphertext.size == 48) {
            "Wallet backup encryption fields have invalid lengths"
        }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(deriveKey(passphrase, salt), "AES"),
            GCMParameterSpec(TAG_BITS, nonce)
        )
        cipher.updateAAD((AAD_PREFIX + public).toByteArray(StandardCharsets.US_ASCII))
        val seed = cipher.doFinal(ciphertext)
        require(seed.size == 32 && publicKey(seed) == public) {
            "Wallet public key does not match the decrypted private key"
        }
        return WalletMaterial(seed, public)
    }

    private fun deriveKey(passphrase: String, salt: ByteArray): ByteArray =
        SCrypt.generate(
            passphrase.toByteArray(StandardCharsets.UTF_8),
            salt,
            SCRYPT_N,
            SCRYPT_R,
            SCRYPT_P,
            KEY_BYTES
        )

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
