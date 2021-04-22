package com.ibm.health.vaccination.sdk.android.cose

import com.google.iot.cbor.*
import com.ibm.health.vaccination.sdk.android.crypto.CertValidator
import com.ibm.health.vaccination.sdk.android.crypto.isRoot
import java.security.GeneralSecurityException
import java.security.PublicKey
import java.security.cert.X509Certificate

/**
 * A COSE object of type cose-sign1 (CBOR tag 18).
 *
 * Also see: https://cose-wg.github.io/cose-spec/#rfc.section.4.2
 */
internal data class CoseSign1(
    val protected: ByteArray,
    val unprotected: Map<Int, Any?>,
    val payload: ByteArray,
    val signature: ByteArray,
) {

    internal val headers: Map<Int, Any?> =
        CborMap.createFromCborByteArray(protected)?.toJavaObject() as? Map<Int, Any?>
            ?: emptyMap()

    internal val kid: ByteArray? = unprotected[4] as? ByteArray
    internal val signatureAlgorithm: CoseSignatureAlgorithm? = CoseSignatureAlgorithm.fromId(headers[1] as? Int)

    /**
     * Checks if this object is valid and also if the signing certificate's whole chain is valid.
     *
     * @throws CoseValidationException if the validation fails.
     */
    fun validate(validator: CertValidator) {
        // TODO: Once the kid contains the SKID we can use that directly. For now, try out all certificates.
        for (cert in validator.trustedCerts) {
            if (!cert.isRoot) {
                try {
                    validate(cert)
                    validator.validate(cert)
                    return
                } catch (e: GeneralSecurityException) {
                    continue
                }
            }
        }
        throw CoseValidationException()
    }

    internal fun validate(cert: X509Certificate) {
        validate(cert.publicKey)
    }

    internal fun validate(publicKey: PublicKey) {
        if (signatureAlgorithm == null) {
            throw MissingSignatureAlgorithmException()
        }
        val data = CborArray.create(
            listOf(
                CborTextString.create("Signature1"),
                CborByteString.create(protected),
                CborByteString.create(byteArrayOf()),
                CborByteString.create(payload),
            )
        ).toCborByteArray()
        signatureAlgorithm.validator.validate(data, publicKey, signature)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CoseSign1

        if (!protected.contentEquals(other.protected)) return false
        if (unprotected != other.unprotected) return false
        if (!payload.contentEquals(other.payload)) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = protected.contentHashCode()
        result = 31 * result + unprotected.hashCode()
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }

    companion object {
        /**
         * Creates CoseSign1 instance from given [byteArray].
         */
        fun fromByteArray(byteArray: ByteArray): CoseSign1 {
            val cborArray = CborArray.createFromCborByteArray(byteArray)
            if (cborArray.majorType != MAJOR_TYPE_ARRAY_OF_DATA_ITEMS)
                throw CoseSign1Exception(
                    "Wrong major type. " +
                        "Expected type is ($MAJOR_TYPE_ARRAY_OF_DATA_ITEMS) - an array of data items. " +
                        "Actual type is (${cborArray.majorType})"
                )
            val list: List<CborObject> = (cborArray as Iterable<CborObject>).toList()
            if (list.size != EXPECTED_CBOR_ARRAY_SIZE)
                throw CoseSign1Exception(
                    "Wrong size of the object array. Expected size is ($EXPECTED_CBOR_ARRAY_SIZE). " +
                        "Actual size is (${list.size})"
                )
            val (protected, unprotected, payload, signature) = list
            return CoseSign1(
                protected.toJavaObject() as ByteArray,
                unprotected.toJavaObject() as Map<Int, Any?>,
                payload.toJavaObject() as ByteArray,
                signature.toJavaObject() as ByteArray
            )
        }

        private const val EXPECTED_CBOR_ARRAY_SIZE: Int = 4

        /**
         * According to the specification.
         * https://tools.ietf.org/html/rfc7049#section-2.1
         */
        private const val MAJOR_TYPE_ARRAY_OF_DATA_ITEMS: Int = 4
    }
}

/** Thrown during [CoseSign1] validation when the signature algorithm is missing in the [CoseSign1] object. */
public class MissingSignatureAlgorithmException : CoseValidationException()

/** Thrown when [CoseSign1.fromByteArray] can't create an instance of CoseSign1. */
public class CoseSign1Exception(message: String) : IllegalArgumentException(message)
