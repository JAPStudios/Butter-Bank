package com.example.butterbank

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Locale

class MoneyTest {
    @Test
    fun formatsTokenAtomicUnitsWithoutFloatingPointRounding() {
        assertEquals("1.23456789", TokenAmount.formatAtomicUnits("123456789", 8))
        assertEquals("1", TokenAmount.formatAtomicUnits("100000000", 8))
        assertEquals("0.00000001", TokenAmount.formatAtomicUnits("1", 8))
        assertEquals("123", TokenAmount.formatAtomicUnits("123", 0))
    }

    @Test
    fun parsesTokenAmountsWithoutRounding() {
        assertEquals(java.math.BigInteger("123456789"), TokenAmount.parsePositiveAtomicUnits("1.23456789", 8))
        assertEquals(java.math.BigInteger.ONE, TokenAmount.parsePositiveAtomicUnits("0.00000001", 8))
        assertNull(TokenAmount.parsePositiveAtomicUnits("1.000000001", 8))
        assertNull(TokenAmount.parsePositiveAtomicUnits("0", 8))
        assertNull(TokenAmount.parsePositiveAtomicUnits("not-a-number", 8))
        assertEquals(java.math.BigInteger("125"), TokenAmount.parsePositiveAtomicUnits("1,25", 2, java.util.Locale.GERMANY))
        assertNull(TokenAmount.parsePositiveAtomicUnits("1.234", 2, java.util.Locale.GERMANY))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsUnsupportedTokenPrecision() {
        TokenAmount.formatAtomicUnits("1", 19)
    }
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
