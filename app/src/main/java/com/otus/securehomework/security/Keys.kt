package com.otus.securehomework.security

import javax.crypto.SecretKey

interface Keys {
    fun getAesSecretKey(): SecretKey
}