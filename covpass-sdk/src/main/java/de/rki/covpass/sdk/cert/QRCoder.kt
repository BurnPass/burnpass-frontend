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

    internal fun recreatePublicKey(public_key_pem_headless: String): PublicKey {
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
        val cose = Sign1Message.DecodeFromBytes(encoded) as? Sign1Message
            ?: throw CoseException("Not a cose-sign1 message")
        val cwt = CBORWebToken.decode(cose.GetContent())
        val public_key_pem_headless =
            defaultCbor.decodeFromByteArray<String>(cwt.rawCbor[USER_PUBLIC_KEY].trimAllStrings().EncodeToBytes())
        val user_public_key = recreatePublicKey(public_key_pem_headless)
        val user_private_key = recreatePrivateKey(user_public_key, privatevalue)
        return user_private_key
    }

    internal fun decodeQRStringcovpass(qr: String): Pair<String, String> {
        if (!qr.startsWith("PV:")) {
            //Bei fehlender private value kann der QR-Code nicht eingelesen werden
            throw IllegalArgumentException("Missing private value, is the correct QR-Code being scanned?")
        }
        val index_bp = qr.indexOf("BP")
        val private_value = qr.substring(3, index_bp)
        val cose = qr.substring(index_bp)
        return Pair(cose, private_value)
    }

    internal fun verify_signature(timestring: String, signature: String, cose_string: String): Boolean {
        val cose_byte = cose_string.removePrefix("BP1:").toByteArray()
        val cose: ByteArray
        try {
            cose = Zlib.decompress(Base45.decode(cose_byte))
        } catch (e: IOException) {
            throw DgcDecodeException("Not a valid zlib compressed DCC")
        }
        val message = Sign1Message.DecodeFromBytes(cose) as? Sign1Message
            ?: throw CoseException("Not a cose-sign1 message")
        val cwt = CBORWebToken.decode(message.GetContent())
        val public_key_pem_headless =
            defaultCbor.decodeFromByteArray<String>(cwt.rawCbor[USER_PUBLIC_KEY].trimAllStrings().EncodeToBytes())
        val user_public_key = recreatePublicKey(public_key_pem_headless)
        val signatureVerify: Signature = Signature.getInstance("SHA1WithECDSA")
        signatureVerify.initVerify(user_public_key)
        signatureVerify.update(timestring.encodeToByteArray())
        val sigVerified = signatureVerify.verify(Base64.decode(signature.toByteArray()))
        return sigVerified
    }

    internal fun decodeQRStringcheck(qr: String): String {
        val current = ZonedDateTime.now()
        var index = qr.indexOf("_")
        if (index == -1) //Fehlt der Timestamp, wird das Zertifikat abgelehnt
        {
            throw IllegalArgumentException("Timestamp missing, Certificated denied")
        }
        val signature = qr.substring(0, index)
        val qr_signless = qr.substring(index + 1)
        index = qr_signless.indexOf("_")
        val qrtime = qr_signless.substring(0, index)

        val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssz", Locale("en"))
        val QRCodetime = ZonedDateTime.parse(qrtime, formatter)
        val diff = Math.abs(ChronoUnit.SECONDS.between(current, QRCodetime))
        //debug print
        println("Time difference: " + (diff))
        val qr_sign_and_timeless = qr_signless.substring(index + 1)
        if (diff > 50) {
            throw TimediffTooBig("Time difference is too big ")
        }
        if (!verify_signature(qrtime, signature, qr_sign_and_timeless)) {
            throw IllegalArgumentException("Signature invalid")
        }
        return qr_sign_and_timeless
    }

    /** Returns the raw COSE ByteArray contained within the certificate. */
    internal fun decodeRawCose(qr: String, is_covpass: Boolean = false): Pair<ByteArray, String> {
        val cose: String
        val privatevalue: String
        if (is_covpass) {
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


    public fun decodeCose(qr: String, is_covpass: Boolean = false): Sign1Message {
        val cose = Sign1Message.DecodeFromBytes(decodeRawCose(qr, is_covpass).first) as? Sign1Message
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
        is_covpass: Boolean = false,
    ): CovCertificate =
        validator.decodeAndValidate(decodeCose(qrContent, is_covpass), allowExpiredCertificates)

    public fun validateTicketing(qrContent: String): TicketingDataInitialization {
        val ticketingData = defaultJson.decodeFromString<TicketingDataInitialization>(qrContent)
        if (ticketingData.protocol == TICKETING_PROTOCOL) {
            return ticketingData
        }
        throw WrongTicketingProtocolException("Wrong Ticketing Protocol")
    }

    private companion object {
        const val TICKETING_PROTOCOL = "DCCVALIDATION"
        private const val USER_PUBLIC_KEY = 73
    }
}

/** Thrown when the decoding of a Document Signer Certificate fails. */
public open class DgcDecodeException(message: String) : IllegalArgumentException(message)

/** Thrown when the decoding of a Ticketing Data fails. */
public open class WrongTicketingProtocolException(message: String) : IllegalArgumentException(message)

/**Bei zu großem Zeitunterschied */
public open class TimediffTooBig(message: String) : IllegalArgumentException(message)
