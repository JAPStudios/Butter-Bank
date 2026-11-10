package com.example.butterbank

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WalletBackupCodecTest {
    @Test
    fun encryptedBackupRoundTripsAndDoesNotContainThePrivateSeed() {
        val material = WalletBackupCodec.generate()
        val passphrase = "correct horse battery staple"
        val backup = WalletBackupCodec.export(material, passphrase)

        assertFalse(backup.contains(material.privateSeed.toHex()))
        val restored = WalletBackupCodec.import(backup, passphrase)
        assertArrayEquals(material.privateSeed, restored.privateSeed)
        assertEquals(material.publicKey, restored.publicKey)
    }

    @Test
    fun wrongPassphraseCannotDecryptWalletBackup() {
        val material = WalletBackupCodec.generate()
        val backup = WalletBackupCodec.export(material, "correct horse battery staple")
        try {
            WalletBackupCodec.import(backup, "incorrect horse battery staple")
            throw AssertionError("wrong passphrase unexpectedly decrypted wallet")
        } catch (_: Exception) {
            // Authentication failure is expected.
        }
    }

    @Test
    fun generatedEd25519SignaturesVerifyAgainstThePublicAddress() {
        val material = WalletBackupCodec.generate()
        val message = "Butter Bank Milkchain transaction".toByteArray()
        val signature = WalletBackupCodec.sign(material.privateSeed, message)
        val publicBytes = material.publicKey.hexToBytes()
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(publicBytes, 0))
        verifier.update(message, 0, message.size)
        assertTrue(verifier.verifySignature(signature))
    }

    @Test
    fun alteredBackupCiphertextFailsAuthentication() {
        val material = WalletBackupCodec.generate()
        val backup = WalletBackupCodec.export(material, "correct horse battery staple")
        val json = org.json.JSONObject(backup)
        val ciphertext = json.getString("ciphertext")
        json.put("ciphertext", (if (ciphertext[0] == 'A') "B" else "A") + ciphertext.substring(1))
        try {
            WalletBackupCodec.import(json.toString(), "correct horse battery staple")
            throw AssertionError("altered backup unexpectedly decrypted")
        } catch (_: Exception) {
            // Authentication failure is expected.
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
