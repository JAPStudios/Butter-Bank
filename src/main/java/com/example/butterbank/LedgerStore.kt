package com.example.butterbank

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypts the complete local ledger snapshot with an AES-256-GCM key held by
 * Android Keystore. The encrypted payload is authenticated; tampering or key
 * invalidation fails closed and never deletes the stored ciphertext.
 */
class LedgerStore(context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    data class Snapshot(val entriesJson: String, val monthlyBudgetCents: Long?)

    @Throws(IOException::class)
    fun load(): Snapshot {
        val encrypted = preferences.getString(KEY_ENCRYPTED_SNAPSHOT, null)
        if (encrypted != null) return decode(encrypted)

        // One-time migration from the previous plaintext SharedPreferences keys.
        val legacyEntries = preferences.getString(KEY_LEGACY_ENTRIES, "[]") ?: "[]"
        val legacyBudget = if (preferences.contains(KEY_LEGACY_BUDGET)) {
            preferences.getLong(KEY_LEGACY_BUDGET, 0L).takeIf { it > 0L }
        } else null
        val snapshot = Snapshot(legacyEntries, legacyBudget)
        val payload = JSONObject().apply {
            put("entries", snapshot.entriesJson)
            if (snapshot.monthlyBudgetCents != null) put("monthlyBudgetCents", snapshot.monthlyBudgetCents)
        }.toString()
        val ciphertext = encrypt(payload)
        val editor = preferences.edit().putString(KEY_ENCRYPTED_SNAPSHOT, ciphertext)
        // Remove plaintext only after the encrypted copy is durably committed.
        editor.remove(KEY_LEGACY_ENTRIES).remove(KEY_LEGACY_BUDGET)
        if (!editor.commit()) throw IOException("Could not securely migrate the local ledger.")
        return snapshot
    }

    @Throws(IOException::class)
    fun save(snapshot: Snapshot) {
        val payload = JSONObject().apply {
            put("entries", snapshot.entriesJson)
            if (snapshot.monthlyBudgetCents != null) put("monthlyBudgetCents", snapshot.monthlyBudgetCents)
        }.toString()
        if (!preferences.edit().putString(KEY_ENCRYPTED_SNAPSHOT, encrypt(payload)).commit()) {
            throw IOException("Could not save the encrypted local ledger.")
        }
    }

    private fun decode(encoded: String): Snapshot {
        try {
            val parts = encoded.split(':', limit = 3)
            if (parts.size != 3 || parts[0] != FORMAT) throw IOException("Unsupported encrypted ledger format.")
            val iv = Base64.decode(parts[1], Base64.NO_WRAP)
            val ciphertext = Base64.decode(parts[2], Base64.NO_WRAP)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(TAG_BITS, iv))
            val plaintext = cipher.doFinal(ciphertext)
            val payload = JSONObject(String(plaintext, StandardCharsets.UTF_8))
            val entries = payload.getString("entries")
            val budget = if (payload.has("monthlyBudgetCents")) {
                payload.getLong("monthlyBudgetCents").takeIf { it > 0L }
            } else null
            return Snapshot(entries, budget)
        } catch (error: IOException) {
            throw error
        } catch (error: Exception) {
            throw IOException("The encrypted ledger could not be unlocked. Stored data was preserved.", error)
        }
    }

    private fun encrypt(plaintext: String): String {
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            val ciphertext = cipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))
            return "$FORMAT:${Base64.encodeToString(cipher.iv, Base64.NO_WRAP)}:${Base64.encodeToString(ciphertext, Base64.NO_WRAP)}"
        } catch (error: Exception) {
            throw IOException("The ledger could not be encrypted.", error)
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
        private const val PREFERENCES = "butter_bank_local"
        private const val KEY_ENCRYPTED_SNAPSHOT = "encrypted_ledger_v1"
        private const val KEY_LEGACY_ENTRIES = "ledger_entries"
        private const val KEY_LEGACY_BUDGET = "monthly_budget_cents"
        private const val KEY_ALIAS = "butter_bank_ledger_aes_v1"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val FORMAT = "v1"
        private const val TAG_BITS = 128
    }
}
