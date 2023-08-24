/*
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 */

package de.rki.covpass.app.detail

import android.animation.ValueAnimator
import android.graphics.Bitmap
import android.os.Bundle
import android.view.View
import android.view.animation.LinearInterpolator
import androidx.core.content.ContextCompat
import com.ensody.reactivestate.android.autoRun
import com.ensody.reactivestate.dispatchers
import com.ensody.reactivestate.get
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.ibm.health.common.android.utils.viewBinding
import com.ibm.health.common.navigation.android.FragmentNav
import com.ibm.health.common.navigation.android.getArgs
import com.ibm.health.common.navigation.android.triggerBackPress
import com.journeyapps.barcodescanner.BarcodeEncoder
import de.rki.covpass.app.R
import de.rki.covpass.app.databinding.DisplayQrCodeBottomsheetContentBinding
import de.rki.covpass.app.dependencies.covpassDeps
import de.rki.covpass.commonapp.BaseBottomSheet
import de.rki.covpass.sdk.cert.models.CovCertificate
import de.rki.covpass.sdk.cert.models.GroupedCertificatesList
import kotlinx.coroutines.invoke
import kotlinx.parcelize.Parcelize
import org.bouncycastle.util.encoders.Base64
import java.security.PrivateKey
import java.security.Signature
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

@Parcelize
internal class DisplayQrCodeFragmentNav(val certId: String) : FragmentNav(DisplayQrCodeFragment::class)

/**
 * Fragment which displays the QR code of a [CovCertificate] on a bottom sheet.
 */
internal class DisplayQrCodeFragment : BaseBottomSheet() {

    private val args: DisplayQrCodeFragmentNav by lazy { getArgs() }

    override val buttonTextRes =
        R.string.vaccination_certificate_detail_view_qrcode_screen_action_button_title
    override val announcementAccessibilityRes: Int =
        R.string.accessibility_vaccination_certificate_detail_view_qrcode_screen_announce

    private val binding by viewBinding(DisplayQrCodeBottomsheetContentBinding::inflate)
    private var valueAnimator: ValueAnimator? = null

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        autoRun { updateViews(get(covpassDeps.certRepository.certs)) }
    }

    override fun onStart() {
        super.onStart()
        context?.let {
            val startColor = ContextCompat.getColor(it, android.R.color.transparent)
            val endColor = ContextCompat.getColor(it, R.color.qr_bottomsheet_background)
            valueAnimator = ValueAnimator.ofArgb(startColor, endColor)
            valueAnimator?.duration = 1000
            valueAnimator?.interpolator = LinearInterpolator()
            val bottomSheetContainer = bottomSheetBinding.bottomSheetContainer
            valueAnimator?.addUpdateListener {
                valueAnimator?.let {
                    if (isResumed) {
                        bottomSheetContainer.setBackgroundColor(it.animatedValue as Int)
                    }
                }
            }
            valueAnimator?.start()
        }
    }

    override fun onStop() {
        super.onStop()
        valueAnimator?.removeAllUpdateListeners()
        context?.let {
            bottomSheetBinding.bottomSheetContainer.setBackgroundColor(
                ContextCompat.getColor(it, android.R.color.transparent),
            )
        }
    }

    private fun updateViews(certificateList: GroupedCertificatesList) {
        val cert = certificateList.getCombinedCertificate(args.certId) ?: return
        EveryXSecond {
            binding.displayQrImageview.setImageBitmap(
                generateQRCode(cert.qrContent, cert.privateKey),
            )
        }
    }

    override fun onActionButtonClicked() {
        triggerBackPress()
    }

    private fun sign(privateKey: PrivateKey, time: String): String {
        val sig = Signature.getInstance("SHA1WithECDSA")
        sig.initSign(privateKey)
        sig.update(time.encodeToByteArray())
        val signatureBytes = sig.sign()
        val signature = Base64.encode(signatureBytes)
        return signature.toString()
    }

    private suspend fun generateQRCode(qrContent: String, privateKey: PrivateKey): Bitmap {
        val current = ZonedDateTime.now() //yyyy-MM-dd HH:mm:ssXX
        //Jahr Monat Tag Stunde Minute Sekunde TimezoneID
        val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssz")
        val currenttime = current.format(formatter)
        //signieren mit dem privatekey
        val signature = sign(privateKey, currenttime)
        val neuerqr = signature + "_" + currenttime + "_" + qrContent
        return dispatchers.default {
            BarcodeEncoder().encodeBitmap(
                neuerqr,
                BarcodeFormat.QR_CODE,
                resources.displayMetrics.widthPixels,
                resources.displayMetrics.widthPixels,
                mapOf(EncodeHintType.MARGIN to 0),
            )
        }
    }
}
