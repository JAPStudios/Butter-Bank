package com.example.butterbank

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class MoneyTest {
    @Test
    fun parsesAmountsExactlyToCents() {
        assertEquals(1234L, Money.parsePositiveCents("12.34"))
        assertEquals(100L, Money.parsePositiveCents("1"))
        assertEquals(5L, Money.parsePositiveCents("0.05"))
    }

    @Test
    fun rejectsInvalidOrOverPreciseAmounts() {
        assertNull(Money.parsePositiveCents(""))
        assertNull(Money.parsePositiveCents("0"))
        assertNull(Money.parsePositiveCents("-1.00"))
        assertNull(Money.parsePositiveCents("1.001"))
        assertNull(Money.parsePositiveCents("not money"))
    }

    @Test
    fun calculatesRecordedBalanceFromIncomeAndExpenses() {
        val entries = listOf(
            LedgerEntry("1", "Pay", 250000, EntryType.INCOME, "Wages", 1L),
            LedgerEntry("2", "Food", 4500, EntryType.EXPENSE, "Groceries", 2L),
            LedgerEntry("3", "Rent", 100000, EntryType.EXPENSE, "Housing", 3L)
        )
        assertEquals(145500L, LedgerMath.balanceCents(entries))
    }
}
