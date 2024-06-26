/*
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 */

package de.rki.covpass.app.main

import android.graphics.Bitmap
import android.os.Bundle
import android.view.View
import com.ensody.reactivestate.android.autoRun
import com.ensody.reactivestate.android.reactiveState
import com.ensody.reactivestate.dispatchers
import com.ensody.reactivestate.get
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.ibm.health.common.android.utils.viewBinding
import com.ibm.health.common.navigation.android.FragmentNav
import com.ibm.health.common.navigation.android.findNavigator
import com.ibm.health.common.navigation.android.getArgs
import com.journeyapps.barcodescanner.BarcodeEncoder
import de.rki.covpass.app.R
import de.rki.covpass.app.certificateswitcher.CertificateSwitcherFragmentNav
import de.rki.covpass.app.databinding.CertificateBinding
import de.rki.covpass.app.dependencies.covpassDeps
import de.rki.covpass.app.detail.DetailFragmentNav
import de.rki.covpass.commonapp.BaseFragment
import de.rki.covpass.sdk.cert.models.BoosterResult
import de.rki.covpass.sdk.cert.models.CovCertificate
import de.rki.covpass.sdk.cert.models.GroupedCertificates
import de.rki.covpass.sdk.cert.models.GroupedCertificatesId
import de.rki.covpass.sdk.cert.models.GroupedCertificatesList
import de.rki.covpass.sdk.cert.models.Recovery
import de.rki.covpass.sdk.cert.models.TestCert
import de.rki.covpass.sdk.cert.models.Vaccination
import de.rki.covpass.sdk.cert.models.VaccinationCertType
import de.rki.covpass.sdk.utils.daysTillNow
import de.rki.covpass.sdk.utils.hoursTillNow
import de.rki.covpass.sdk.utils.monthTillNow
import kotlinx.coroutines.invoke
import kotlinx.parcelize.Parcelize
import org.bouncycastle.util.encoders.Base64
import java.security.PrivateKey
import java.security.Signature
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.Locale

@Parcelize
internal class CertificateFragmentNav(val certId: GroupedCertificatesId) :
    FragmentNav(CertificateFragment::class)

/**
 * Fragment which shows a [CovCertificate]
 */
internal class CertificateFragment : BaseFragment() {

    internal val args: CertificateFragmentNav by lazy { getArgs() }
    private val viewModel by reactiveState { CertificateViewModel(scope) }
    private val binding by viewBinding(CertificateBinding::inflate)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        autoRun {
            // TODO: Optimize this, so we only update if our cert has changed and not something else
            updateViews(get(covpassDeps.certRepository.certs))
        }
    }

    private fun updateViews(certificateList: GroupedCertificatesList) {
        val certId = args.certId
        val groupedCertificate = certificateList.getGroupedCertificates(certId) ?: return
        val mainCombinedCertificate = groupedCertificate.getMainCertificate()
        val mainCertificate = mainCombinedCertificate.covCertificate
        val isMarkedAsFavorite = certificateList.isMarkedAsFavorite(certId)

        val certStatus = mainCombinedCertificate.status
        val isFavoriteButtonVisible = certificateList.certificates.size > 1

        EveryXSecond {
            binding.certificateCard.qrCodeImage = if (mainCombinedCertificate.isRevoked) {
                generateQRCode(REVOKED_QRCODE, mainCombinedCertificate.privateKey)
            } else {
                generateQRCode(mainCombinedCertificate.qrContent, mainCombinedCertificate.privateKey)
            }
        }

        val showBoosterNotification = !groupedCertificate.hasSeenBoosterDetailNotification &&
            groupedCertificate.boosterNotification.result == BoosterResult.Passed

        when (val dgcEntry = mainCertificate.dgcEntry) {
            is Vaccination -> {
                when (dgcEntry.type) {
                    VaccinationCertType.VACCINATION_FULL_PROTECTION -> {
                        val vaccination = mainCertificate.dgcEntry as Vaccination
                        val isJanssenFullProtection =
                            vaccination.isJanssen && vaccination.doseNumber == 2
                        binding.certificateCard.createCertificateCardView(
                            mainCertificate.fullName,
                            isMarkedAsFavorite,
                            certStatus,
                            if (
                                vaccination.isBooster &&
                                !isJanssenFullProtection &&
                                !groupedCertificate.isCertVaccinationNotBoosterAfterJanssen(mainCertificate)
                            ) {
                                getString(R.string.certificate_type_booster)
                            } else {
                                getString(R.string.certificate_type_basic_immunisation)
                            },
                            if (
                                vaccination.isBooster &&
                                !isJanssenFullProtection &&
                                !groupedCertificate.isCertVaccinationNotBoosterAfterJanssen(mainCertificate)
                            ) {
                                getString(
                                    R.string.certificate_timestamp_days,
                                    vaccination.occurrence?.atStartOfDay(ZoneId.systemDefault())
                                        ?.toInstant()?.daysTillNow(),
                                )
                            } else {
                                getString(
                                    R.string.certificate_timestamp_months,
                                    vaccination.occurrence?.atStartOfDay(ZoneId.systemDefault())
                                        ?.toInstant()?.monthTillNow(),
                                )
                            },
                            if (showBoosterNotification) {
                                R.drawable.booster_notification_icon
                            } else {
                                R.drawable.main_cert_status_complete
                            },
                        )
                    }
                    VaccinationCertType.VACCINATION_COMPLETE -> {
                        val vaccination = mainCertificate.dgcEntry as Vaccination
                        binding.certificateCard.createCertificateCardView(
                            mainCertificate.fullName,
                            isMarkedAsFavorite,
                            certStatus,
                            "",
                            getString(
                                R.string.certificate_timestamp_months,
                                vaccination.occurrence?.atStartOfDay(ZoneId.systemDefault())
                                    ?.toInstant()?.monthTillNow(),
                            ),
                            R.drawable.main_cert_status_incomplete,
                        )
                    }
                    VaccinationCertType.VACCINATION_INCOMPLETE -> {
                        val vaccination = mainCertificate.dgcEntry as Vaccination
                        binding.certificateCard.createCertificateCardView(
                            mainCertificate.fullName,
                            isMarkedAsFavorite,
                            certStatus,
                            "",
                            getString(
                                R.string.certificate_timestamp_months,
                                vaccination.occurrence?.atStartOfDay(ZoneId.systemDefault())
                                    ?.toInstant()?.monthTillNow(),
                            ),
                            R.drawable.main_cert_status_incomplete,
                        )
                    }
                }
            }
            is TestCert -> {
                val test = mainCertificate.dgcEntry as TestCert
                binding.certificateCard.createCertificateCardView(
                    mainCertificate.fullName,
                    isMarkedAsFavorite,
                    certStatus,
                    if (test.testType == TestCert.PCR_TEST) {
                        getString(R.string.certificate_type_pcrtest)
                    } else {
                        getString(R.string.certificate_type_rapidtest)
                    },
                    getString(
                        R.string.certificate_timestamp_hours,
                        test.sampleCollection?.hoursTillNow(),
                    ),
                    R.drawable.main_cert_test_blue,
                )
            }
            is Recovery -> {
                val recovery = mainCertificate.dgcEntry as Recovery
                binding.certificateCard.createCertificateCardView(
                    mainCertificate.fullName,
                    isMarkedAsFavorite,
                    certStatus,
                    getString(R.string.certificate_type_recovery),
                    getString(
                        R.string.certificate_timestamp_months,
                        recovery.firstResult?.atStartOfDay(ZoneId.systemDefault())?.toInstant()
                            ?.monthTillNow(),
                    ),
                    R.drawable.main_cert_status_complete,
                )
            }
            // .let{} to enforce exhaustiveness
        }.let {}

        binding.certificateCard.isFavoriteButtonVisible = isFavoriteButtonVisible
        binding.certificateCard.setOnFavoriteClickListener {
            viewModel.onFavoriteClick(args.certId)
        }
        binding.certificateCard.setOnCardClickListener {
            cardClick(groupedCertificate)
        }
        binding.certificateCard.setOnCertificateStatusClickListener {
            cardClick(groupedCertificate)
        }
    }

    private fun cardClick(groupedCertificate: GroupedCertificates) {
        findNavigator().push(
            if (groupedCertificate.getListOfImportantCerts().isNotEmpty()) {
                CertificateSwitcherFragmentNav(args.certId)
            } else {
                DetailFragmentNav(args.certId)
            },
        )
    }

    private fun sign(privateKey: PrivateKey, time: String): String {
        val sig = Signature.getInstance("SHA1WithECDSA")
        sig.initSign(privateKey)
        sig.update(time.encodeToByteArray())
        val signatureBytes = sig.sign()
        return Base64.toBase64String(signatureBytes)
    }

    private suspend fun generateQRCode(qrContent: String, privateKey: PrivateKey): Bitmap {
        var displayedqr = qrContent
        if (!qrContent.equals(REVOKED_QRCODE)) {
            val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssz", Locale("en"))
            val currenttime = ZonedDateTime.now().format(formatter)
            //signieren mit dem privatekey
            val signature = sign(privateKey, currenttime)
            displayedqr = signature + "_" + currenttime + "_" + qrContent
        }
        return dispatchers.default {
            BarcodeEncoder().encodeBitmap(
                displayedqr,
                BarcodeFormat.QR_CODE,
                resources.displayMetrics.widthPixels,
                resources.displayMetrics.widthPixels,
                mapOf(EncodeHintType.MARGIN to 0),
            )
        }
    }

    private companion object {
        const val REVOKED_QRCODE = " "
    }
}
