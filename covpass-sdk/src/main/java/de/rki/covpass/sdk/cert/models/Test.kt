/*
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 */

@file:UseSerializers(ZonedDateTimeSerializer::class)

package de.rki.covpass.sdk.cert.models

import de.rki.covpass.sdk.utils.serialization.ZonedDateTimeSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import java.time.ZonedDateTime

/**
 * Data model for the tests inside a Digital Green Certificate.
 */
@Serializable
public data class Test(
    @SerialName("tg")
    val targetDisease: String = "",
    @SerialName("tt")
    val testType: String = "",
    @SerialName("nm")
    val testName: String = "",
    @SerialName("ma")
    val manufacturer: String = "",
    @SerialName("sc")
    val sampleCollection: ZonedDateTime? = null,
    @SerialName("tr")
    val testResult: String = "",
    @SerialName("tc")
    val testingCentre: String = "",
    @SerialName("co")
    val country: String = "",
    @SerialName("is")
    val certificateIssuer: String = "",
    @SerialName("ci")
    override val id: String = ""
) : DGCEntry {
    public companion object {
        public const val PCR_TEST: String = "LP6464-4"
        public const val ANTIGEN_TEST: String = "LP217198-3"
        public const val POSITIVE_RESULT: String = "260373001"
        public const val NEGATIVE_RESULT: String = "260415000"
        public const val PCR_TEST_EXPIRY_TIME_HOURS: Long = 72
        public const val ANTIGEN_TEST_EXPIRY_TIME_HOURS: Long = 48
    }
}
