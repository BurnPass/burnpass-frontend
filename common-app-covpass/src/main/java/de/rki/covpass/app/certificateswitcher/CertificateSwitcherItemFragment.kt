/*
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 */

package de.rki.covpass.app.certificateswitcher

import android.graphics.Bitmap
import android.os.Bundle
import android.view.View
import com.ensody.reactivestate.android.autoRun
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
import de.rki.covpass.app.databinding.CertificateSwitcherItemBinding
import de.rki.covpass.app.dependencies.covpassDeps
import de.rki.covpass.app.detail.DetailFragmentNav
import de.rki.covpass.commonapp.BaseFragment
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
internal class CertificateSwitcherItemFragmentNav(
    val certId: GroupedCertificatesId,
    val id: String,
) : FragmentNav(CertificateSwitcherItemFragment::class)

internal class CertificateSwitcherItemFragment : BaseFragment() {

    internal val args: CertificateSwitcherItemFragmentNav by lazy { getArgs() }
    private val binding by viewBinding(CertificateSwitcherItemBinding::inflate)

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
        val combinedCovCertificate = groupedCertificate.certificates.find {
            it.covCertificate.dgcEntry.id == args.id
        } ?: return
        val covCertificate = combinedCovCertificate.covCertificate
        val certStatus = combinedCovCertificate.status

        EveryXSecond {
            binding.certificateCard.qrCodeImage =
                generateQRCode(combinedCovCertificate.qrContent, combinedCovCertificate.privateKey)
        }

        when (val dgcEntry = covCertificate.dgcEntry) {
            is Vaccination -> {
                when (dgcEntry.type) {
                    VaccinationCertType.VACCINATION_FULL_PROTECTION -> {
                        val vaccination = covCertificate.dgcEntry as Vaccination
                        val isJanssenFullProtection =
                            vaccination.isJanssen && vaccination.doseNumber == 2
                        binding.certificateCard.createCertificateSwitcherItemView(
                            certStatus,
                            if (
                                vaccination.isBooster &&
                                !isJanssenFullProtection &&
                                !groupedCertificate.isCertVaccinationNotBoosterAfterJanssen(covCertificate)
                            ) {
                                getString(R.string.certificate_type_booster)
                            } else {
                                getString(R.string.certificate_type_basic_immunisation)
                            },
                            if (
                                vaccination.isBooster &&
                                !isJanssenFullProtection &&
                                !groupedCertificate.isCertVaccinationNotBoosterAfterJanssen(covCertificate)
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
                            R.drawable.main_cert_status_complete,
                        )
                    }
                    VaccinationCertType.VACCINATION_COMPLETE -> {
                        val vaccination = covCertificate.dgcEntry as Vaccination
                        binding.certificateCard.createCertificateSwitcherItemView(
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
                        val vaccination = covCertificate.dgcEntry as Vaccination
                        binding.certificateCard.createCertificateSwitcherItemView(
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
                val test = covCertificate.dgcEntry as TestCert
                binding.certificateCard.createCertificateSwitcherItemView(
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
                val recovery = covCertificate.dgcEntry as Recovery
                binding.certificateCard.createCertificateSwitcherItemView(
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

        binding.certificateCard.setOnCardClickListener {
            findNavigator().push(
                DetailFragmentNav(args.certId),
            )
        }
    }

    private fun sign(privateKey: PrivateKey, time: String): String {
        val sig = Signature.getInstance("SHA1WithECDSA")
        sig.initSign(privateKey)
        sig.update(time.encodeToByteArray())
        val signatureBytes = sig.sign()
        return Base64.toBase64String(signatureBytes)
    }

    private suspend fun generateQRCode(qrContent: String, privateKey: PrivateKey): Bitmap {
        val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssz", Locale("en"))
        val currenttime = ZonedDateTime.now().format(formatter)
        //signieren mit dem privatekey
        val signature = sign(privateKey, currenttime)
        val displayedqr = signature + "_" + currenttime + "_" + qrContent
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
}
