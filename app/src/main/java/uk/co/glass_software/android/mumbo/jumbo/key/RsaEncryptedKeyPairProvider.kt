/*
 * Copyright (C) 2017 Glass Software Ltd
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package uk.co.glass_software.android.mumbo.jumbo.key

import android.util.Base64
import com.facebook.android.crypto.keychain.SecureRandomFix
import com.facebook.crypto.CryptoConfig
import com.facebook.crypto.MacConfig
import io.reactivex.annotations.NonNull
import uk.co.glass_software.android.boilerplate.Boilerplate.logger
import uk.co.glass_software.android.boilerplate.utils.log.Logger
import uk.co.glass_software.android.boilerplate.utils.preferences.SharedPrefsDelegate

internal class RsaEncryptedKeyPairProvider internal constructor(
    private val rsaEncrypter: RsaEncrypter,
    private val logger: Logger,
    private val keyPairDelegate: SharedPrefsDelegate<String>,
    private val cryptoConfig: CryptoConfig
) {

    private var keyPair: String? by keyPairDelegate
    private var pair: KeyPair? = null
    private val isKeyEncryptionEnabled = false //FIXME

    val cipherKey = getOrGenerate().cipherKey
    val macKey = getOrGenerate().macKey

    @Synchronized
    @Throws(Exception::class)
    private fun getOrGenerate(): KeyPair {
        return if (pair == null) {
            val keyPairValue = keyPair

            if (keyPairValue == null) {
                val newPair = generateNewKeyPair()

                val cipherKey = if (newPair.isEncrypted) newPair.encryptedCipherKey else newPair.cipherKey
                val macKey = if (newPair.isEncrypted) newPair.encryptedMacKey else newPair.macKey

                keyPair = (
                        (if (newPair.isEncrypted) "1" else "0")
                                + DELIMITER
                                + toBase64(cipherKey)
                                + DELIMITER
                                + toBase64(macKey)
                        )

                pair = newPair
                return newPair
            } else {
                val strings = keyPairValue
                    .split(DELIMITER.toRegex())
                    .dropLastWhile { it.isEmpty() }
                    .toTypedArray()

                val isKeyPairEncrypted = "1" == strings[0]
                val storedCipherKey = fromBase64(strings[1])
                val storedMacKey = fromBase64(strings[2])

                val newPair = if (isKeyPairEncrypted) KeyPair(
                    rsaEncrypter.decrypt(storedCipherKey),
                    rsaEncrypter.decrypt(storedMacKey),
                    storedCipherKey,
                    storedMacKey,
                    true
                )
                else KeyPair(
                    storedCipherKey,
                    storedMacKey,
                    null,
                    null,
                    false
                )
                pair = newPair
                return newPair
            }
        } else pair!!
    }

    fun isEncryptionKeySecure(): Boolean =
        try {
            getOrGenerate().isEncrypted
        } catch (e: Exception) {
            logger.e(this, e, "Could not check if the key pair was encrypted")
            false
        }

    fun initialise() {
        try {
            getOrGenerate()
        } catch (e: Exception) {
            logger.e(this, e, "Could not initialise RsaEncryptedKeyPairProvider")
        }
    }

    @Synchronized
    fun destroyKeys() {
        pair = null
        keyPairDelegate.clear()
    }

    @Synchronized
    private fun generateNewKeyPair(): KeyPair {
        val cipherKey = ByteArray(cryptoConfig.keyLength)
        val macKey = ByteArray(MacConfig.DEFAULT.keyLength)

        val secureRandom = SecureRandomFix.createLocalSecureRandom()
        secureRandom.nextBytes(cipherKey)
        secureRandom.nextBytes(macKey)

        var encryptedCipherKey: ByteArray?
        var encryptedMacKey: ByteArray?
        try {
            encryptedCipherKey = rsaEncrypter.encrypt(cipherKey)
            encryptedMacKey = rsaEncrypter.encrypt(macKey)
        } catch (e: Exception) {
            encryptedCipherKey = null
            encryptedMacKey = null
        }

        val isEncrypted: Boolean
        if (encryptedCipherKey == null || encryptedMacKey == null || !isKeyEncryptionEnabled) {
            logger.e(this, "RSA encrypter could not encrypt the keys")
            encryptedCipherKey = null
            encryptedMacKey = null
            isEncrypted = false
        } else {
            isEncrypted = true
        }

        return KeyPair(
            cipherKey,
            macKey,
            encryptedCipherKey,
            encryptedMacKey,
            isEncrypted
        )
    }

    private fun toBase64(@NonNull bytes: ByteArray?) =
        Base64.encodeToString(bytes, Base64.DEFAULT)

    private fun fromBase64(@NonNull string: String?) =
        Base64.decode(string, Base64.DEFAULT)

    companion object {
        private const val DELIMITER = "~"
    }

}