/*
 * (C) Copyright IBM Deutschland GmbH 2021
 * (C) Copyright IBM Corp. 2021
 */

package de.rki.covpass.sdk.cert

import COSE.CoseException
import COSE.Sign1Message
import de.rki.covpass.base45.Base45
import de.rki.covpass.sdk.cert.models.CBORWebToken
import de.rki.covpass.sdk.cert.models.CovCertificate
import de.rki.covpass.sdk.dependencies.defaultCbor
import de.rki.covpass.sdk.dependencies.defaultJson
import de.rki.covpass.sdk.ticketing.TicketingDataInitialization
import de.rki.covpass.sdk.utils.Zlib
import de.rki.covpass.sdk.utils.trimAllStrings
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.decodeFromString
import org.bouncycastle.util.encoders.Base64
import java.io.IOException
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import java.util.Locale

/**
 * Used to encode/decode QR code string.
 */


public class QRCoder(private val validator: CertValidator) {

    internal fun recreatePublicKey(encoded_cose: ByteArray): PublicKey {
        val cose = Sign1Message.DecodeFromBytes(encoded_cose) as? Sign1Message
            ?: throw CoseException("Not a cose-sign1 message")
        val cwt = CBORWebToken.decode(cose.GetContent())
        val public_key_pem_headless =
            defaultCbor.decodeFromByteArray<String>(cwt.rawCbor[USER_PUBLIC_KEY].trimAllStrings().EncodeToBytes())
        val kf = KeyFactory.getInstance("ECDSA")
        val encoded: ByteArray = Base64.decode(public_key_pem_headless)
        val keySpec = X509EncodedKeySpec(encoded)
        return kf.generatePublic(keySpec)
    }

    internal fun recreatePrivateKey(user_public_key: PublicKey, private_value: String): PrivateKey {
        val private_value_int = BigInteger(private_value)
        val kf = KeyFactory.getInstance("ECDSA")
        val public_spec = kf.getKeySpec(
            user_public_key, ECPublicKeySpec::class.java,
        )
        val priv_spec = ECPrivateKeySpec(private_value_int, public_spec.params)
        return kf.generatePrivate(priv_spec)
    }

    public fun extractUserKeys(qr: String): PrivateKey {
        val (encoded, privatevalue) = decodeRawCose(qr, true)
        if (privatevalue.equals("")) {
            throw IllegalArgumentException("Missing private value, is the correct QR-Code being scanned?")
        }
        val user_public_key = recreatePublicKey(encoded)
        val user_private_key = recreatePrivateKey(user_public_key, privatevalue)
        return user_private_key
    }

    internal fun verify_signature(timestring: String, signature: String, encoded_cose_string: String): Boolean {
        val encoded_cose_byte = encoded_cose_string.removePrefix("BP1:").toByteArray()
        val encoded_cose: ByteArray
        try {
            encoded_cose = Zlib.decompress(Base45.decode(encoded_cose_byte))
        } catch (e: IOException) {
            throw DgcDecodeException("Not a valid zlib compressed DCC")
        }
        val user_public_key = recreatePublicKey(encoded_cose)
        val signatureVerifier: Signature = Signature.getInstance("SHA1WithECDSA")
        signatureVerifier.initVerify(user_public_key)
        signatureVerifier.update(timestring.encodeToByteArray())
        return signatureVerifier.verify(Base64.decode(signature.toByteArray()))
    }

    internal fun decodeQRStringcovpass(qr: String): Pair<String, String> {
        if (!qr.startsWith("PV:")) {
            //Bei fehlender private value kann der QR-Code nicht eingelesen werden
            //Wird er jedoch intern überprüft, kann ohne PV fortgeführt werden
            return Pair(qr, "")
        }
        val index_bp = qr.indexOf("BP")
        val private_value = qr.substring(3, index_bp)
        val cose = qr.substring(index_bp)
        return Pair(cose, private_value)
    }

    internal fun decodeQRStringcheck(qr: String): String {
        if (!qr.contains("_")) {
            throw IllegalArgumentException("Timestamp missing, Certificated denied")
        }
        val qrsplits: List<String> = qr.split("_")
        if (qrsplits.size != 3) {
            //lässt sich der QRCode nicht in genau 3 Teile teilen, fehlt etwas oder es ist ein falscher QRCode
            throw IllegalArgumentException("Timestamp/Signature missing or wrong QRCode, Certificated denied")
        }
        //assigning each part to a val for clarity
        val signature = qrsplits[0]
        val qrtimestamp = qrsplits[1]
        val certificateQR = qrsplits[2]

        val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssz", Locale("en"))
        val qrdatetime = ZonedDateTime.parse(qrtimestamp, formatter)
        val timedifference = Math.abs(ChronoUnit.SECONDS.between(ZonedDateTime.now(), qrdatetime))
        if (timedifference > 50) {
            throw TimediffTooBig("The time difference between creation and scanning of the certificat is too big")
        }
        //Entfernen der Signatur und des Zeitstempels ergibt das Zertifikat als cose
        if (!verify_signature(qrtimestamp, signature, certificateQR)) {
            throw IllegalArgumentException("Signature invalid")
        }
        return certificateQR
    }

    /** Returns the raw COSE ByteArray contained within the certificate. */
    internal fun decodeRawCose(qr: String, is_burnpass: Boolean = false): Pair<ByteArray, String> {
        val cose: String
        val privatevalue: String
        if (is_burnpass) {
            val pair = decodeQRStringcovpass(qr)
            cose = pair.first
            privatevalue = pair.second
        } else {
            cose = decodeQRStringcheck(qr)
            privatevalue = ""
        }
        val qrContent = cose.removePrefix("BP1:").toByteArray()
        try {
            return Pair(Zlib.decompress(Base45.decode(qrContent)), privatevalue)
        } catch (e: IOException) {
            throw DgcDecodeException("Not a valid zlib compressed DCC")
        }
    }


    public fun decodeCose(qr: String, is_burnpass: Boolean = false): Sign1Message {
        val cose = Sign1Message.DecodeFromBytes(decodeRawCose(qr, is_burnpass).first) as? Sign1Message
            ?: throw CoseException("Not a cose-sign1 message")
        return cose
    }

    /**
     * Converts a [qrContent] to a [CovCertificate] data model.
     *
     * @throws ExpiredCwtException If the [CBORWebToken] has expired.
     * @throws BadCoseSignatureException If the signature validation failed.
     * @throws CoseException For generic COSE errors.
     * @throws GeneralSecurityException For generic cryptography errors.
     */
    public fun decodeCovCert(
        qrContent: String,
        allowExpiredCertificates: Boolean = false,
        is_burnpass: Boolean = false,
    ): CovCertificate =
        validator.decodeAndValidate(decodeCose(qrContent, is_burnpass), allowExpiredCertificates)

    public fun validateTicketing(qrContent: String): TicketingDataInitialization {
        val ticketingData = defaultJson.decodeFromString<TicketingDataInitialization>(qrContent)
        if (ticketingData.protocol == TICKETING_PROTOCOL) {
            return ticketingData
        }
        throw WrongTicketingProtocolException("Wrong Ticketing Protocol")
    }

    private companion object {
        const val TICKETING_PROTOCOL = "DCCVALIDATION"
        private const val USER_PUBLIC_KEY = 8
    }
}

/** Thrown when the decoding of a Document Signer Certificate fails. */
public open class DgcDecodeException(message: String) : IllegalArgumentException(message)

/** Thrown when the decoding of a Ticketing Data fails. */
public open class WrongTicketingProtocolException(message: String) : IllegalArgumentException(message)

/**Bei zu großem Zeitunterschied */
public open class TimediffTooBig(message: String) : IllegalArgumentException(message)
