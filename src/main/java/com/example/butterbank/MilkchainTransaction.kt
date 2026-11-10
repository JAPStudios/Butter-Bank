package com.example.butterbank

import org.json.JSONObject
import java.math.BigInteger
import java.nio.charset.StandardCharsets

object MilkchainTransaction {
    fun canonicalBytes(
        chainId: String,
        sender: String,
        recipient: String,
        amount: BigInteger,
        nonce: BigInteger
    ): ByteArray {
        // Match milkchain.node.signing_bytes: sorted keys and compact UTF-8 JSON.
        val json = "{\"amount\":$amount,\"chain_id\":${JSONObject.quote(chainId)}," +
            "\"fee\":0,\"nonce\":$nonce,\"recipient\":${JSONObject.quote(recipient)}," +
            "\"sender\":${JSONObject.quote(sender)}}"
        return json.toByteArray(StandardCharsets.UTF_8)
    }

    fun signedJson(canonical: ByteArray, signatureHex: String): String {
        val payload = String(canonical, StandardCharsets.UTF_8)
        require(payload.endsWith("}")) { "canonical transaction JSON is malformed" }
        require(signatureHex.matches(Regex("^[0-9a-f]{128}$"))) {
            "Ed25519 transaction signature must be 64 bytes of hexadecimal"
        }
        return payload.dropLast(1) + ",\"signature\":\"$signatureHex\"}"
    }
}
