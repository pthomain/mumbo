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


import uk.co.glass_software.android.boilerplate.utils.log.Logger
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.NoSuchPaddingException

internal class RsaEncrypter(
    private val keyStore: KeyStore?,
    private val logger: Logger,
    private val alias: String
) {

    private val cipherInstance: Cipher
        @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class, NoSuchPaddingException::class)
        get() = Cipher.getInstance(RSA_MODE, CIPHER_PROVIDER)

    private val privateKeyEntry: KeyStore.PrivateKeyEntry?
        @Throws(NoSuchAlgorithmException::class, UnrecoverableEntryException::class, KeyStoreException::class)
        get() {
            if (keyStore ==
                null
            ) {
                logger.e(this, "KeyStore is null, no encryption on device")
                return null
            } else {
                logger.d(this, "Found a key pair in the KeyStore")
                return keyStore.getEntry(
                    alias, null
                ) as KeyStore.PrivateKeyEntry
            }
        }

    @Throws(Exception::class)
    fun encrypt(secret: ByteArray): ByteArray? {
        val privateKeyEntry = privateKeyEntry

        if (privateKeyEntry == null) {
            logger.e(this, "Private key entry was null")
            return null
        }

        val inputCipher = cipherInstance
        inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.certificate.publicKey)

        val outputStream = ByteArrayOutputStream()
        val cipherOutputStream = CipherOutputStream(outputStream, inputCipher)
        cipherOutputStream.write(secret)
        cipherOutputStream.close()

        return outputStream.toByteArray()
    }

    @Throws(Exception::class)
    fun decrypt(encrypted: ByteArray): ByteArray? {
        val privateKeyEntry = privateKeyEntry

        if (privateKeyEntry == null) {
            logger.e(this, "Private key entry was null")
            return null
        }

        val outputCipher = cipherInstance
        outputCipher.init(Cipher.DECRYPT_MODE, privateKeyEntry.privateKey)

        val inputStream = ByteArrayInputStream(encrypted)
        val cipherInputStream = CipherInputStream(inputStream, outputCipher)
        val values = cipherInputStream.readBytes()

        val bytes = ByteArray(values.size)
        for (i in bytes.indices) {
            bytes[i] = values[i]
        }
        return bytes
    }

    companion object {
        private val CIPHER_PROVIDER = "AndroidOpenSSL"
        private val RSA_MODE = "RSA/ECB/PKCS1Padding"
    }

}
