package com.example.butterbank

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import java.io.IOException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Stores an Ed25519 seed encrypted by an AES key held in Android Keystore.
 * Exportable backups use WalletBackupCodec's interoperable scrypt/AES-GCM format.
 */
class WalletStore(context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun hasWallet(): Boolean = preferences.contains(KEY_CIPHERTEXT)

    fun publicAddress(): String? = preferences.getString(KEY_PUBLIC_KEY, null)

    @Throws(IOException::class)
    fun createWallet(): String {
        if (hasWallet()) throw IllegalStateException("A wallet already exists on this device.")
        val material = WalletBackupCodec.generate()
        return try {
            store(material)
            material.publicKey
        } finally {
            material.privateSeed.fill(0)
        }
    }

    @Throws(IOException::class)
    fun importBackup(backup: String, passphrase: String): String {
        if (hasWallet()) throw IllegalStateException("A wallet already exists on this device.")
        val material = WalletBackupCodec.import(backup, passphrase)
        return try {
            store(material)
            material.publicKey
        } finally {
            material.privateSeed.fill(0)
        }
    }

    @Throws(IOException::class)
    fun exportBackup(passphrase: String): String {
        val seed = decryptSeed()
        return try {
            val public = publicAddress() ?: throw IOException("Wallet public key is missing.")
            WalletBackupCodec.export(WalletMaterial(seed, public), passphrase)
        } finally {
            seed.fill(0)
        }
    }

    @Throws(IOException::class)
    fun sign(message: ByteArray): ByteArray {
        val seed = decryptSeed()
        return try {
            WalletBackupCodec.sign(seed, message)
        } finally {
            seed.fill(0)
        }
    }

    private fun store(material: WalletMaterial) {
        val expectedPublic = WalletBackupCodec.publicKey(material.privateSeed)
        if (expectedPublic != material.publicKey) throw IllegalArgumentException("Wallet keypair is inconsistent")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val encrypted = cipher.doFinal(material.privateSeed)
        val committed = preferences.edit()
            .putString(KEY_PUBLIC_KEY, material.publicKey)
            .putString(KEY_IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            .putString(KEY_CIPHERTEXT, Base64.encodeToString(encrypted, Base64.NO_WRAP))
            .commit()
        if (!committed) throw IOException("Could not save the encrypted wallet on this device.")
    }

    private fun decryptSeed(): ByteArray {
        val public = publicAddress() ?: throw IOException("No wallet is stored on this device.")
        val ivText = preferences.getString(KEY_IV, null) ?: throw IOException("Wallet encryption nonce is missing.")
        val ciphertextText = preferences.getString(KEY_CIPHERTEXT, null)
            ?: throw IOException("Encrypted wallet data is missing.")
        try {
            val iv = Base64.decode(ivText, Base64.NO_WRAP)
            val ciphertext = Base64.decode(ciphertextText, Base64.NO_WRAP)
            if (iv.size != 12 || ciphertext.size != 48) throw IOException("Encrypted wallet data is malformed.")
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(TAG_BITS, iv))
            val seed = cipher.doFinal(ciphertext)
            if (WalletBackupCodec.publicKey(seed) != public) {
                throw IOException("Wallet public key does not match its stored private key.")
            }
            return seed
        } catch (error: IOException) {
            throw error
        } catch (error: Exception) {
            throw IOException("The encrypted wallet could not be unlocked. Stored data was preserved.", error)
        }
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    companion object {
        private const val PREFERENCES = "butter_bank_wallet"
        private const val KEY_PUBLIC_KEY = "public_key"
        private const val KEY_IV = "seed_iv"
        private const val KEY_CIPHERTEXT = "seed_ciphertext"
        private const val KEY_ALIAS = "butter_bank_ed25519_seed_v1"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val TAG_BITS = 128
    }
}
