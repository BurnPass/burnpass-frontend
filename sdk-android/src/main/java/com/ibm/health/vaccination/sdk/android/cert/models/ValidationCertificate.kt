@file:UseSerializers(LocalDateSerializer::class, InstantSerializer::class)

package com.ibm.health.vaccination.sdk.android.cert.models

import com.ibm.health.vaccination.sdk.android.utils.serialization.InstantSerializer
import com.ibm.health.vaccination.sdk.android.utils.serialization.LocalDateSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import java.time.Instant
import java.time.LocalDate

/**
 * Data model for the validation certificate.
 */
@Serializable
public data class ValidationCertificate(

    // Information inside the CWT
    val issuer: String = "",
    val validFrom: Instant? = null,
    val validUntil: Instant? = null,

    @SerialName("nam")
    val name: Name = Name(),
    @SerialName("dob")
    val birthDate: LocalDate? = null,
    @SerialName("v")
    val vaccinations: List<Vaccination> = emptyList(),
    @SerialName("ver")
    val version: String = "",
) {
    public val vaccination: Vaccination
        get() = vaccinations.first()

    public val hasFullProtection: Boolean
        get() = vaccinations.any { it.hasFullProtection }

    public val fullName: String by lazy {
        listOfNotNull(
            name.givenName ?: name.givenNameTransliterated,
            name.familyName ?: name.familyNameTransliterated
        ).joinToString(" ")
    }
}
