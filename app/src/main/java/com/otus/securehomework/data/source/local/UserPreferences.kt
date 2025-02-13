package com.otus.securehomework.data.source.local

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.otus.securehomework.security.CipherUtils
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject

private const val dataStoreFile: String = "securePref"

class UserPreferences
@Inject constructor(
    private val context: Context,
    private val cipherUtils: CipherUtils
) {

    val accessToken: Flow<String?>
        get() = context.dataStore.data.map { preferences ->
            preferences[ACCESS_TOKEN_IV]?.let { iv ->
                preferences[ACCESS_TOKEN]?.let { encrypted ->
                    cipherUtils.decrypt(encrypted, iv)
                }
            }
        }

    val refreshToken: Flow<String?>
        get() = context.dataStore.data.map { preferences ->
            preferences[REFRESH_TOKEN_IV]?.let { iv ->
                preferences[REFRESH_TOKEN]?.let { encrypted ->
                    cipherUtils.decrypt(encrypted, iv)
                }
            }
        }

    suspend fun saveAccessTokens(accessToken: String?, refreshToken: String?) {
        if (accessToken == null || refreshToken == null) return
        val accessTokenPair = cipherUtils.encrypt(accessToken)
        val refreshTokenPair = cipherUtils.encrypt(refreshToken)
        context.dataStore.edit { preferences ->
            preferences[ACCESS_TOKEN] = accessTokenPair.first
            preferences[ACCESS_TOKEN_IV] = accessTokenPair.second
            preferences[REFRESH_TOKEN] = refreshTokenPair.first
            preferences[REFRESH_TOKEN_IV] = refreshTokenPair.second
        }
    }

    suspend fun clear() {
        context.dataStore.edit { preferences ->
            preferences.clear()
        }
    }

    companion object {
        private val Context.dataStore by preferencesDataStore(name = dataStoreFile)
        private val ACCESS_TOKEN = stringPreferencesKey("key_access_token")
        private val ACCESS_TOKEN_IV = stringPreferencesKey("iv_access_token")
        private val REFRESH_TOKEN = stringPreferencesKey("key_refresh_token")
        private val REFRESH_TOKEN_IV = stringPreferencesKey("iv_refresh_token")
    }
}