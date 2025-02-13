package com.otus.securehomework.presentation.splash

import android.content.Context
import android.os.Build
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Observer
import androidx.lifecycle.asLiveData
import androidx.lifecycle.lifecycleScope
import com.otus.securehomework.R
import com.otus.securehomework.data.source.local.UserPreferences
import com.otus.securehomework.presentation.auth.AuthActivity
import com.otus.securehomework.presentation.home.HomeActivity
import com.otus.securehomework.presentation.startNewActivity
import com.otus.securehomework.security.BiometricAuth
import com.otus.securehomework.security.BiometricCipher.Companion.BIOMETRIC_SHARED_PREFERENCE_USE_KEY
import com.otus.securehomework.security.CipherUtils.Companion.SHARED_PREFERENCE_NAME
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class SplashActivity : AppCompatActivity() {

    @Inject
    lateinit var userPreferences: UserPreferences

    private val sharedPreferences by lazy {
        this.applicationContext.getSharedPreferences(
            SHARED_PREFERENCE_NAME,
            Context.MODE_PRIVATE
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_splash)

        userPreferences.accessToken.asLiveData().observe(this, Observer {
            if (it == null) {
                navigateToAuth()
            } else {
                val isBiometricAuthRequired =
                    sharedPreferences.getBoolean(BIOMETRIC_SHARED_PREFERENCE_USE_KEY, false)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && isBiometricAuthRequired) {
                    lifecycleScope.launch {
                        BiometricAuth().biometricAuthenticate(
                            activity = this@SplashActivity,
                            title = "Biometric authenticate",
                            subtitle = "Use biometry to authenticate",
                            description = "Dismiss to logout and disable biometry",
                            onSuccess = ::navigateToHome,
                            onDismissOrFailed = ::disableBiometry,
                            onNoBiometry = ::navigateToHome
                        )
                    }
                } else {
                    navigateToHome()
                }
            }
        })
    }

    private fun disableBiometry() {
        lifecycleScope.launch {
            sharedPreferences.edit().apply {
                putBoolean(
                    BIOMETRIC_SHARED_PREFERENCE_USE_KEY, false
                )
                apply()
            }
            userPreferences.clear()
            navigateToAuth()
        }

    }

    private fun navigateToHome() {
        startNewActivity(HomeActivity::class.java)
    }

    private fun navigateToAuth() {
        startNewActivity(AuthActivity::class.java)
    }
}