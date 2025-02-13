package com.otus.securehomework.security

import android.os.Build
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
import androidx.biometric.auth.AuthPromptErrorException
import androidx.biometric.auth.AuthPromptFailureException
import androidx.biometric.auth.AuthPromptHost
import androidx.biometric.auth.Class2BiometricAuthPrompt
import androidx.biometric.auth.Class3BiometricAuthPrompt
import androidx.biometric.auth.authenticate
import androidx.fragment.app.FragmentActivity

class BiometricAuth {

    @RequiresApi(Build.VERSION_CODES.M)
    suspend fun biometricAuthenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
        description: String,
        onSuccess: () -> Unit,
        onDismissOrFailed: () -> Unit,
        onNoBiometry: () -> Unit,
    ) {
        when (BIOMETRIC_SUCCESS) {
            BiometricManager.from(activity)
                .canAuthenticate(BIOMETRIC_STRONG),
                -> {
                val biometricCipher = BiometricCipher(activity.applicationContext)
                val encryptor = biometricCipher.getEncryptor()

                val authPrompt =
                    Class3BiometricAuthPrompt.Builder(
                        title,
                        "dismiss"
                    )
                        .apply {
                            setSubtitle(subtitle)
                            setDescription(description)
                            setConfirmationRequired(true)
                        }.build()

                try {
                    authPrompt.authenticate(AuthPromptHost(activity), encryptor)
                    onSuccess()
                } catch (e: AuthPromptErrorException) {
                    onDismissOrFailed()
                } catch (e: AuthPromptFailureException) {
                    onDismissOrFailed()
                }
            }

            BiometricManager.from(activity)
                .canAuthenticate(BIOMETRIC_WEAK),
                -> {
                val authPrompt = Class2BiometricAuthPrompt.Builder(
                    title,
                    "dismiss"
                ).apply {
                    setSubtitle(subtitle)
                    setDescription(description)
                    setConfirmationRequired(true)
                }.build()

                try {
                    authPrompt.authenticate(AuthPromptHost(activity))
                    onSuccess()
                } catch (e: AuthPromptErrorException) {
                    onDismissOrFailed()
                } catch (e: AuthPromptFailureException) {
                    onDismissOrFailed()
                }
            }

            else -> onNoBiometry()
        }
    }
}