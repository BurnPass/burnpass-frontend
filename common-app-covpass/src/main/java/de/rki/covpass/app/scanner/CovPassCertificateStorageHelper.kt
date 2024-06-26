/*
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 */

package de.rki.covpass.app.scanner

import com.ensody.reactivestate.SuspendMutableValueFlow
import de.rki.covpass.sdk.cert.models.CertValidationResult
import de.rki.covpass.sdk.cert.models.CombinedCovCertificate
import de.rki.covpass.sdk.cert.models.CovCertificate
import de.rki.covpass.sdk.cert.models.GroupedCertificatesId
import de.rki.covpass.sdk.cert.models.GroupedCertificatesList
import de.rki.covpass.sdk.cert.models.ReissueState
import de.rki.covpass.sdk.cert.models.ReissueType
import de.rki.covpass.sdk.cert.models.isExpired
import de.rki.covpass.sdk.cert.models.isInExpiryPeriod
import java.security.PrivateKey

public object CovPassCertificateStorageHelper {
    //remove the private value if present when storing, as it is seperately stored and should not be displayed
    internal fun removePV(qrContent: String): String {
        val newqrContent: String
        val index_bp = qrContent.indexOf("BP")
        newqrContent = qrContent.substring(index_bp)
        return newqrContent
    }

    public suspend fun addNewCertificate(
        groupedCertificatesList: SuspendMutableValueFlow<GroupedCertificatesList>,
        covCertificate: CovCertificate,
        qrContent: String,
        privateKey: PrivateKey,
    ): GroupedCertificatesId? {
        var certId: GroupedCertificatesId? = null
        groupedCertificatesList.update {
            certId = it.addNewCertificate(
                CombinedCovCertificate(
                    covCertificate = covCertificate,
                    qrContent = removePV(qrContent),
                    timestamp = System.currentTimeMillis(),
                    status = when {
                        covCertificate.isExpired() -> CertValidationResult.Expired
                        covCertificate.isInExpiryPeriod() -> CertValidationResult.ExpiryPeriod
                        else -> CertValidationResult.Valid
                    },
                    hasSeenBoosterNotification = false,
                    hasSeenBoosterDetailNotification = false,
                    hasSeenExpiryNotification = false,
                    boosterNotificationRuleIds = mutableListOf(),
                    hasSeenReissueNotification = false,
                    hasSeenExpiredReissueNotification = false,
                    hasSeenReissueDetailNotification = false,
                    isRevoked = false,
                    hasSeenRevokedNotification = false,
                    reissueState = ReissueState.None,
                    reissueType = ReissueType.None,
                    privateKey = privateKey,
                ),
            )
        }
        return certId
    }
}
