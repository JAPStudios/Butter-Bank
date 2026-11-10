package com.example.butterbank

import java.math.BigDecimal
import java.math.RoundingMode
import java.text.DecimalFormatSymbols
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
    fun parsePositiveCents(raw: String, locale: Locale = Locale.getDefault()): Long? {
        val input = raw.trim()
        if (input.isEmpty()) return null

        val symbols = DecimalFormatSymbols.getInstance(locale)
        val decimalSeparator = symbols.decimalSeparator
        val groupingSeparator = symbols.groupingSeparator

        // The entry field expects an ungrouped amount. Reject grouping characters
        // rather than silently interpreting a thousands separator as a decimal.
        if (groupingSeparator != decimalSeparator && input.contains(groupingSeparator)) {
            return null
        }

        val normalized = if (decimalSeparator == '.') input else input.replace(decimalSeparator, '.')
        return try {
            val amount = BigDecimal(normalized)
            if (amount <= BigDecimal.ZERO) {
                null
            } else {
                amount.setScale(2, RoundingMode.UNNECESSARY)
                    .movePointRight(2)
                    .longValueExact()
            }
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
    fun totalCents(entries: Iterable<LedgerEntry>, type: EntryType): Long =
        entries.filter { it.type == type }.fold(0L) { total, entry ->
            Math.addExact(total, entry.amountCents)
        }

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
