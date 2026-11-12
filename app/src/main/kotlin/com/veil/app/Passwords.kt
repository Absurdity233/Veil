package com.veil.app

/**
 * Password rules and strength hints, for the account vault.
 *
 * The length is enforced rather than suggested. That is not paternalism: the
 * vault is sealed under a key derived from the password, and the server holds the
 * sealed blob. So password strength is the *entire* defence against someone who
 * steals that blob, and Argon2id makes each guess expensive without making a short
 * password long.
 */

/** Minimum password length. */
const val MIN_PASSWORD_LENGTH = 12

/** Rejects a password that is too short, returning the reason rather than a boolean. */
fun checkPassword(password: String): String? =
    if (password.length < MIN_PASSWORD_LENGTH) {
        "at least $MIN_PASSWORD_LENGTH characters: this password is the only thing " +
            "protecting the account, because the server cannot check it for you"
    } else {
        null
    }

/**
 * A rough strength estimate.
 *
 * Deliberately crude: real entropy cannot be estimated from one string, and
 * claiming otherwise would be worse than a coarse bucket. What it catches is the
 * password that passes the length check while being a keyboard walk or a single
 * repeated character - a pattern Argon2id does not help against.
 */
fun describeStrength(password: String): String {
    if (password.length < MIN_PASSWORD_LENGTH) return "too short"

    val classes = listOf(
        password.any { it.isLowerCase() },
        password.any { it.isUpperCase() },
        password.any { it.isDigit() },
        password.any { !it.isLetterOrDigit() },
    ).count { it }

    val variety = password.toSet().size.toDouble() / password.length

    if (variety < 0.3) return "weak: too repetitive"
    if (password.length >= 20 && classes >= 3) return "strong"
    if (password.length >= 16 || classes >= 3) return "reasonable"
    return "weak: add length or variety"
}
