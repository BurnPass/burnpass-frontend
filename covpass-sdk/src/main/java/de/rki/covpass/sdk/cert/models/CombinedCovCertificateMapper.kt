package de.rki.covpass.sdk.cert.models

import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.time.ZoneId
import java.time.ZonedDateTime


public fun CombinedCovCertificateLocal.toCombinedCovCertificate(
    status: CertValidationResult,
): CombinedCovCertificate =
    CombinedCovCertificate(
        covCertificate = covCertificate,
        qrContent = qrContent,
        timestamp = timestamp,
        status = status,
        hasSeenBoosterNotification = hasSeenBoosterNotification,
        hasSeenBoosterDetailNotification = hasSeenBoosterDetailNotification,
        hasSeenExpiryNotification = hasSeenExpiryNotification,
        boosterNotificationRuleIds = boosterNotificationRuleIds,
        hasSeenReissueNotification = hasSeenReissueNotification,
        hasSeenExpiredReissueNotification = hasSeenExpiredReissueNotification,
        hasSeenReissueDetailNotification = hasSeenReissueDetailNotification,
        hasSeenRevokedNotification = hasSeenRevokedNotification,
        isRevoked = isRevoked,
        reissueState = reissueState,
        reissueType = reissueType,
        privateKey = KeyFactory.getInstance("ECDSA").generatePrivate(PKCS8EncodedKeySpec(privateKey)),
    )


public fun CombinedCovCertificate.toCombinedCovCertificateLocal(): CombinedCovCertificateLocal =
    CombinedCovCertificateLocal(
        covCertificate = covCertificate,
        qrContent = qrContent,
        timestamp = timestamp,
        hasSeenBoosterNotification = hasSeenBoosterNotification,
        hasSeenBoosterDetailNotification = hasSeenBoosterDetailNotification,
        hasSeenExpiryNotification = hasSeenExpiryNotification,
        boosterNotificationRuleIds = boosterNotificationRuleIds,
        hasSeenReissueNotification = hasSeenReissueNotification,
        hasSeenExpiredReissueNotification = hasSeenExpiredReissueNotification,
        hasSeenReissueDetailNotification = hasSeenReissueDetailNotification,
        hasSeenRevokedNotification = hasSeenRevokedNotification,
        isRevoked = isRevoked,
        reissueState = reissueState,
        reissueType = reissueType,
        privateKey = privateKey.encoded,
    )

public fun CovCertificate.isInExpiryPeriod(): Boolean =
    ZonedDateTime.ofInstant(
        validUntil,
        ZoneId.systemDefault(),
    ).minusDays(28).isBefore(ZonedDateTime.now())

public fun CovCertificate.isExpired(): Boolean =
    ZonedDateTime.ofInstant(
        validUntil,
        ZoneId.systemDefault(),
    ).isBefore(ZonedDateTime.now())
