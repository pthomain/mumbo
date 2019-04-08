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

package uk.co.glass_software.android.mumbo.jumbo.key.provider.pre_m.rsa


import uk.co.glass_software.android.boilerplate.core.utils.log.Logger
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream

internal class RsaEncrypter(
    private val keyStore: KeyStore?,
    private val logger: Logger,
    private val alias: String
) {

    private fun getCipherInstance() = Cipher.getInstance(
        RSA_MODE,
        CIPHER_PROVIDER
    )

    private fun getPrivateKeyEntry() =
        if (keyStore == null) {
            logger.e(this, "KeyStore is null, no encryption on device")
            null
        } else {
            try {
                val entry = keyStore.getEntry(
                    alias,
                    null
                ) as KeyStore.PrivateKeyEntry
                logger.d(this, "Found a key pair in the KeyStore")
                entry
            } catch (e: Exception) {
                logger.e(this, e, "Found a key pair in the KeyStore but could not load it")
                null
            }
        }

    @Throws(Exception::class)
    fun encrypt(secret: ByteArray): ByteArray? {
        val privateKeyEntry = getPrivateKeyEntry()

        if (privateKeyEntry == null) {
            logger.e(this, "Private key entry was null")
            return null
        }

        val inputCipher = getCipherInstance()
        inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.certificate.publicKey)

        val outputStream = ByteArrayOutputStream()
        val cipherOutputStream = CipherOutputStream(outputStream, inputCipher)
        cipherOutputStream.write(secret)
        cipherOutputStream.close()

        return outputStream.toByteArray()
    }

    @Throws(Exception::class)
    fun decrypt(encrypted: ByteArray): ByteArray? {
        val privateKeyEntry = getPrivateKeyEntry()

        if (privateKeyEntry == null) {
            logger.e(this, "Private key entry was null")
            return null
        }

        val outputCipher = getCipherInstance()
        outputCipher.init(Cipher.DECRYPT_MODE, privateKeyEntry.privateKey)

        val inputStream = ByteArrayInputStream(encrypted)
        return CipherInputStream(inputStream, outputCipher).readBytes()
    }

    companion object {
        private val CIPHER_PROVIDER = "AndroidOpenSSL"
        private val RSA_MODE = "RSA/ECB/PKCS1Padding"
    }

}
