package com.ibm.health.vaccination.sdk.android.cert.models

import kotlinx.serialization.Serializable

/**
 * Data model which contains a list of [CombinedVaccinationCertificate] and a pointer to the favorite / own certificate.
 */
@Serializable
public data class VaccinationCertificateList(
    val certificates: MutableList<CombinedVaccinationCertificate> = mutableListOf(),
    var favoriteCertId: String? = null,
) {

    public fun addCertificate(certificate: CombinedVaccinationCertificate) {
        val vaccination = certificate.vaccinationCertificate.vaccinations
        if (certificates.none {
            vaccination.first().id ==
                it.vaccinationCertificate.vaccination.id
        }
        ) {
            certificates.add(certificate)
            if (certificates.size == 1) {
                favoriteCertId =
                    vaccination.first().id
            }
        } else {
            throw CertAlreadyExistsException()
        }
    }
}

/** This exception is thrown when certificates list already has such certificate */
public class CertAlreadyExistsException : RuntimeException()
