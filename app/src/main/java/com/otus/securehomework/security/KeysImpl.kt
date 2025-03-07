package com.otus.securehomework.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.otus.securehomework.security.CipherUtils.Companion.AES_ALGORITHM
import com.otus.securehomework.security.CipherUtils.Companion.KEY_PROVIDER
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.inject.Inject

@RequiresApi(Build.VERSION_CODES.M)
class KeysImpl @Inject constructor() : Keys {

    private val keyStore by lazy { KeyStore.getInstance(KEY_PROVIDER).apply { load(null) } }

    override fun getAesSecretKey(): SecretKey {
        return keyStore.getKey(AES_KEY_ALIAS, null) as? SecretKey ?: generateAesSecretKey()
    }

    private fun generateAesSecretKey(): SecretKey {
        return getKeyGenerator().generateKey()
    }

    private fun getKeyGenerator() = KeyGenerator.getInstance(AES_ALGORITHM, KEY_PROVIDER).apply {
        init(getKeyGenSpec())
    }

    private fun getKeyGenSpec(): KeyGenParameterSpec {
        return KeyGenParameterSpec.Builder(
            AES_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .setUserAuthenticationRequired(false)
            .setRandomizedEncryptionRequired(false)
            .setKeySize(KEY_LENGTH)
            .build()
    }

    companion object {
        const val KEY_LENGTH = 256
        const val AES_KEY_ALIAS = "AES_HOMEWORK"
    }
}