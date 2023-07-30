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
import de.rki.covpass.sdk.dependencies.defaultJson
import de.rki.covpass.sdk.ticketing.TicketingDataInitialization
import de.rki.covpass.sdk.utils.Zlib
import kotlinx.serialization.decodeFromString
import java.io.IOException
import java.security.GeneralSecurityException
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit

/**
 * Used to encode/decode QR code string.
 */

public class QRCoder(private val validator: CertValidator) {

    internal fun decodeQRStringcovpass(qr: String): Pair<String, String> {
        if (!qr.startsWith("PV:")) {
            //Bei fehlender private value kann der QR-Code nicht eingelesen werden
            println("Missing private value")
            throw IllegalArgumentException("Missing private value, is the correct QR-Code being scanned?")
        }
        val index_bp = qr.indexOf("BP")
        var private_value = qr.substring(0, index_bp)
        private_value = private_value.substring(3)
        val cose = qr.substring(index_bp)
        //val private_value_int = private_value.toInt()
        return Pair(cose,private_value)
    }

    internal fun decodeQRStringcheck(qr: String): String {
        val current = ZonedDateTime.now()
        val index = qr.indexOf("_")
        if (index == -1) //Fehlt der Timestamp, wird das Zertifikat abgelehnt
        {
            println("Timestamp missing, Certificated denied")
            throw IllegalArgumentException("Timestamp missing, Certificated denied")
        }
        val qrtime = qr.substring(0, index)
        val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ssz")
        val QRCodetime = ZonedDateTime.parse(qrtime, formatter) //
        val diff = Math.abs(ChronoUnit.SECONDS.between(current, QRCodetime))
        println("Time difference: " + (diff))
        val qr_ohne_zeit = qr.substring(index + 1)
        if (diff > 50) {
            throw TimediffTooBig("Time difference is too big ")
        }
        println("checker decoder success")
        println(qr_ohne_zeit)
        return qr_ohne_zeit
    }

    /** Returns the raw COSE ByteArray contained within the certificate. */
    internal fun decodeRawCose(qr: String, is_covpass: Boolean = false): ByteArray {
        var cose: String
        var privatevalue: String
        if (is_covpass) {
            val pair = decodeQRStringcovpass(qr)
            cose = pair.first
            privatevalue = pair.second
        } else {
            cose = decodeQRStringcheck(qr)
        }

        val qrContent = cose.removePrefix("BP1:").toByteArray()
        try {
            return Zlib.decompress(Base45.decode(qrContent))
        } catch (e: IOException) {
            throw DgcDecodeException("Not a valid zlib compressed DCC")
        }
    }

    public fun decodeCose(qr: String, is_covpass: Boolean = false): Sign1Message =
        Sign1Message.DecodeFromBytes(decodeRawCose(qr, is_covpass)) as? Sign1Message
            ?: throw CoseException("Not a cose-sign1 message")

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
    }
}

/** Thrown when the decoding of a Document Signer Certificate fails. */
public open class DgcDecodeException(message: String) : IllegalArgumentException(message)

/** Thrown when the decoding of a Ticketing Data fails. */
public open class WrongTicketingProtocolException(message: String) : IllegalArgumentException(message)

/**Bei zu großem Zeitunterschied */
public open class TimediffTooBig(message: String) : IllegalArgumentException(message)
