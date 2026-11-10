package com.example.butterbank

import java.math.BigInteger
import org.junit.Assert.assertEquals
import org.junit.Test

class MilkchainTransactionTest {
    @Test
    fun canonicalPayloadMatchesPythonSigningFieldOrderAndFormatting() {
        val sender = "11".repeat(32)
        val recipient = "22".repeat(32)
        val canonical = MilkchainTransaction.canonicalBytes(
            "milkchain-main",
            sender,
            recipient,
            BigInteger("123456789"),
            BigInteger("7")
        )
        assertEquals(
            """{"amount":123456789,"chain_id":"milkchain-main","fee":0,"nonce":7,"recipient":"$recipient","sender":"$sender"}""",
            String(canonical, Charsets.UTF_8)
        )
    }

    @Test
    fun signedTransactionAppendsOnlyTheEd25519SignatureField() {
        val canonical = MilkchainTransaction.canonicalBytes(
            "milkchain-main", "11".repeat(32), "22".repeat(32),
            BigInteger.ONE, BigInteger.ONE
        )
        val signature = "ab".repeat(64)
        assertEquals(
            String(canonical, Charsets.UTF_8).dropLast(1) + ",\"signature\":\"$signature\"}",
            MilkchainTransaction.signedJson(canonical, signature)
        )
    }
}
