package com.example.butterbank

import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

class BankLedger(
    private val hybridAccount: Account,
    private val creditLimit: Double
) {
    data class Transaction(
        val timestamp: String,
        val description: String,
        val amount: Double
    )

    private val history = mutableListOf<Transaction>()
    private val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
    private var creditUsed: Double = 0.0

    fun addFunds(amount: Double): Boolean {
        if (amount <= 0.0) return false
        hybridAccount.balance += amount
        addHistory("Cash deposit", amount)
        return true
    }

    fun spend(amount: Double): Boolean {
        if (amount <= 0.0) return false

        val fromCash = minOf(amount, hybridAccount.balance)
        val remaining = amount - fromCash

        if (remaining > availableCredit()) return false

        hybridAccount.balance -= fromCash
        creditUsed += remaining

        addHistory("Purchase", -amount)
        return true
    }

    fun repayCreditFromCash(amount: Double): Boolean {
        if (amount <= 0.0) return false
        if (hybridAccount.balance < amount) return false

        val repayment = minOf(amount, creditUsed)
        if (repayment <= 0.0) return false

        hybridAccount.balance -= repayment
        creditUsed -= repayment
        addHistory("Credit repayment", -repayment)
        return true
    }

    fun getAccount(): Account = hybridAccount

    fun getCreditUsed(): Double = creditUsed

    fun availableCredit(): Double = creditLimit - creditUsed

    fun getCreditLimit(): Double = creditLimit

    fun getHistory(): List<Transaction> = history.reversed()

    private fun addHistory(description: String, amount: Double) {
        history += Transaction(
            timestamp = LocalDateTime.now().format(formatter),
            description = description,
            amount = amount
        )
    }
}
