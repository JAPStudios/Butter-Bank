package com.example.butterbank

import java.math.BigDecimal
import java.math.RoundingMode
import java.text.NumberFormat
import java.util.Locale

enum class EntryType {
    INCOME,
    EXPENSE
}

data class LedgerEntry(
    val id: String,
    val description: String,
    val amountCents: Long,
    val type: EntryType,
    val category: String,
    val timestampMillis: Long
)

object Money {
    fun parsePositiveCents(raw: String): Long? {
        return try {
            val amount = BigDecimal(raw.trim())
            if (amount <= BigDecimal.ZERO) return null
            amount.setScale(2, RoundingMode.UNNECESSARY)
                .movePointRight(2)
                .longValueExact()
        } catch (_: NumberFormatException) {
            null
        } catch (_: ArithmeticException) {
            null
        }
    }

    fun formatCents(cents: Long, locale: Locale = Locale.getDefault()): String {
        return NumberFormat.getCurrencyInstance(locale)
            .format(BigDecimal.valueOf(cents, 2))
    }
}

object LedgerMath {
    fun balanceCents(entries: Iterable<LedgerEntry>): Long =
        entries.fold(0L) { balance, entry ->
            val signedAmount = if (entry.type == EntryType.INCOME) {
                entry.amountCents
            } else {
                -entry.amountCents
            }
            Math.addExact(balance, signedAmount)
        }
}
