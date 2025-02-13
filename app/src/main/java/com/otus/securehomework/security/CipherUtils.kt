package com.otus.securehomework.security

import android.util.Base64
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.inject.Inject

private const val AES_TRANSFORMATION = "AES/CBC/PKCS7Padding"

class CipherUtils @Inject constructor(keys: Keys) {
    private val key = keys.getAesSecretKey()

    fun encrypt(plainText: String): Pair<String, String> {
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        val iv = getInitializationVector(cipher.blockSize)
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(iv))
        val encodedBytes = cipher.doFinal(plainText.toByteArray())
        val encrypted = Base64.encodeToString(encodedBytes, Base64.NO_WRAP)
        val ivString = Base64.encodeToString(iv, Base64.NO_WRAP)
        return Pair(encrypted, ivString)
    }

    private fun getInitializationVector(blockSize: Int): ByteArray {
        val iv = ByteArray(blockSize)
        SecureRandom().nextBytes(iv)
        return iv
    }

    fun decrypt(encrypted: String, iv: String): String {
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(Base64.decode(iv, Base64.NO_WRAP)))
        val encryptedBytes = Base64.decode(encrypted, Base64.NO_WRAP)
        val decodedBytes = cipher.doFinal(encryptedBytes)
        return String(decodedBytes, Charsets.UTF_8)
    }

    companion object {
        const val KEY_PROVIDER = "AndroidKeyStore"
        const val AES_KEY_ALIAS = "AES_HOMEWORK"
        const val AES_ALGORITHM = "AES"
        const val KEY_LENGTH = 256
        const val RSA_ALGORITHM = "RSA"
        const val SHARED_PREFERENCE_NAME = "AppSharedPreferences"
        const val ENCRYPTED_KEY_NAME = "RSAEncryptedKeysKeyName"
        const val RSA_MODE_LESS_THAN_M = "RSA/ECB/PKCS1Padding"
        const val RSA_KEY_ALIAS = "RSA_HOMEWORK"
    }
}