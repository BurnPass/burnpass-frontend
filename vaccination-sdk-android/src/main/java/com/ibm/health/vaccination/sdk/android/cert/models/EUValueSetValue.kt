/*
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 */

package com.ibm.health.vaccination.sdk.android.cert.models

import kotlinx.serialization.Serializable

@Serializable
internal data class EUValueSetValue(
    val display: String,
    val lang: String,
    val active: Boolean,
    val system: String,
    val version: String
)
