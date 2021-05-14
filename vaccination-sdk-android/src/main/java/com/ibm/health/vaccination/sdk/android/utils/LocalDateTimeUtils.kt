package com.ibm.health.vaccination.sdk.android.utils

import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

/**
 * Formats a local date to e.g. "12.03.1989, 14:52".
 */
public fun LocalDateTime.formatDateTime(): String {
    val formatter = DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM)
    return format(formatter)
}
