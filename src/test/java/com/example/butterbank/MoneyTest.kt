package com.example.butterbank

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Locale

class MoneyTest {
    @Test
    fun parsesAmountsExactlyToCents() {
        assertEquals(1234L, Money.parsePositiveCents("12.34", Locale.US))
        assertEquals(100L, Money.parsePositiveCents("1", Locale.US))
        assertEquals(5L, Money.parsePositiveCents("0.05", Locale.US))
    }

    @Test
    fun parsesLocaleDecimalSeparator() {
        assertEquals(1234L, Money.parsePositiveCents("12,34", Locale.GERMANY))
        assertEquals(1234L, Money.parsePositiveCents("12,34", Locale.FRANCE))
    }

    @Test
    fun rejectsInvalidOrOverPreciseAmounts() {
        assertNull(Money.parsePositiveCents("", Locale.US))
        assertNull(Money.parsePositiveCents("0", Locale.US))
        assertNull(Money.parsePositiveCents("-1.00", Locale.US))
        assertNull(Money.parsePositiveCents("1.001", Locale.US))
        assertNull(Money.parsePositiveCents("1,234.56", Locale.US))
        assertNull(Money.parsePositiveCents("not money", Locale.US))
    }

    @Test
    fun calculatesRecordedBalanceFromIncomeAndExpenses() {
        val entries = listOf(
            LedgerEntry("1", "Pay", 250000, EntryType.INCOME, "Wages", 1L),
            LedgerEntry("2", "Food", 4500, EntryType.EXPENSE, "Groceries", 2L),
            LedgerEntry("3", "Rent", 100000, EntryType.EXPENSE, "Housing", 3L)
        )
        assertEquals(145500L, LedgerMath.balanceCents(entries))
        assertEquals(250000L, LedgerMath.totalCents(entries, EntryType.INCOME))
        assertEquals(104500L, LedgerMath.totalCents(entries, EntryType.EXPENSE))
    }

    @Test(expected = ArithmeticException::class)
    fun rejectsOverflowingIncomeTotals() {
        val entries = listOf(
            LedgerEntry("1", "A", Long.MAX_VALUE, EntryType.INCOME, "Other", 1L),
            LedgerEntry("2", "B", 1L, EntryType.INCOME, "Other", 2L)
        )
        LedgerMath.totalCents(entries, EntryType.INCOME)
    }

    @Test(expected = ArithmeticException::class)
    fun rejectsOverflowingBalance() {
        val entries = listOf(
            LedgerEntry("1", "A", Long.MAX_VALUE, EntryType.INCOME, "Other", 1L),
            LedgerEntry("2", "B", 1L, EntryType.INCOME, "Other", 2L)
        )
        LedgerMath.balanceCents(entries)
    }
}
