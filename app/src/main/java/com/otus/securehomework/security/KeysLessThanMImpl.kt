package com.otus.securehomework.security

import android.content.Context
import android.security.KeyPairGeneratorSpec
import android.util.Base64
import com.otus.securehomework.security.CipherUtils.Companion.AES_ALGORITHM
import com.otus.securehomework.security.CipherUtils.Companion.KEY_PROVIDER
import com.otus.securehomework.security.CipherUtils.Companion.SHARED_PREFERENCE_NAME
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.util.Calendar
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.security.auth.x500.X500Principal

class KeysLessThanMImpl @Inject constructor(private val applicationContext: Context) : Keys {
    private val sharedPreferences by lazy {
        applicationContext.getSharedPreferences(
            SHARED_PREFERENCE_NAME,
            Context.MODE_PRIVATE
        )
    }
    private val keyStore by lazy { KeyStore.getInstance(KEY_PROVIDER).apply { load(null) } }

    override fun getAesSecretKey(): SecretKey {
        return getAesSecretKeyLesThanM() ?: generateAesSecretKey()

    }

    private fun generateAesSecretKey(): SecretKey {
        return generateAndSaveAesSecretKeyLessThanM()
    }

    private fun getAesSecretKeyLesThanM(): SecretKey? {
        val encryptedKeyBase64Encoded = getSecretKeyFromSharedPreferences()
        return encryptedKeyBase64Encoded?.let {
            val encryptedKey = Base64.decode(it, Base64.DEFAULT)
            val key = rsaDecryptKey(encryptedKey)
            SecretKeySpec(key, AES_ALGORITHM)
        }
    }

    private fun rsaDecryptKey(encryptedKey: ByteArray?): ByteArray {
        val cipher = Cipher.getInstance(RSA_MODE_LESS_THAN_M)
        cipher.init(Cipher.DECRYPT_MODE, getRsaPrivateKey())
        return cipher.doFinal(encryptedKey)
    }

    private fun rsaEncryptKey(secret: ByteArray?): ByteArray {
        val cipher = Cipher.getInstance(RSA_MODE_LESS_THAN_M)
        cipher.init(Cipher.ENCRYPT_MODE, getRsaPublicKey())
        return cipher.doFinal(secret)
    }

    private fun getRsaPrivateKey() =
        keyStore.getKey(RSA_KEY_ALIAS, null) as? PrivateKey ?: generateRsaSecretKeys().private

    private fun getRsaPublicKey() =
        keyStore.getCertificate(RSA_KEY_ALIAS)?.publicKey ?: generateRsaSecretKeys().public

    private fun generateRsaSecretKeys(): KeyPair {
        val start = Calendar.getInstance()
        val end = Calendar.getInstance()
        end.add(Calendar.YEAR, 10)
        val spec = KeyPairGeneratorSpec.Builder(applicationContext)
            .setAlias(RSA_KEY_ALIAS)
            .setSubject(X500Principal("CN=$RSA_KEY_ALIAS"))
            .setSerialNumber(BigInteger.TEN)
            .setStartDate(start.time)
            .setEndDate(end.time)
            .build()

        return KeyPairGenerator.getInstance(RSA_ALGORITHM, KEY_PROVIDER).run {
            initialize(spec)
            generateKeyPair()
        }
    }

    private fun getSecretKeyFromSharedPreferences(): String? {
        return sharedPreferences.getString(ENCRYPTED_KEY_NAME, null)
    }

    private fun generateAndSaveAesSecretKeyLessThanM(): SecretKey {
        val key = ByteArray(16)
        SecureRandom().run { nextBytes(key) }
        val encryptedKeyBase64Encoded = Base64.encodeToString(rsaEncryptKey(key), Base64.DEFAULT)
        sharedPreferences.edit().apply {
            putString(ENCRYPTED_KEY_NAME, encryptedKeyBase64Encoded)
            apply()
        }
        return SecretKeySpec(key, AES_ALGORITHM)
    }

    companion object {
        const val RSA_ALGORITHM = "RSA"
        const val ENCRYPTED_KEY_NAME = "RSAEncryptedKeysKeyName"
        const val RSA_MODE_LESS_THAN_M = "RSA/ECB/PKCS1Padding"
        const val RSA_KEY_ALIAS = "RSA_HOMEWORK"
    }
}