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

package uk.co.glass_software.android.mumbo.jumbo

import io.reactivex.annotations.NonNull
import uk.co.glass_software.android.boilerplate.utils.log.Logger
import javax.crypto.Cipher

//see https://medium.com/@ericfu/securely-storing-secrets-in-an-android-application-501f030ae5a3#.qcgaaeaso
internal class PreMEncryptionManager internal constructor(
    logger: Logger,
    private val secureKeyProvider: SecureKeyProvider
) : BaseJumboEncryptionManager(logger) {

    override val isEncryptionSupported = secureKeyProvider.isEncryptionSupported

    val isEncryptionKeySecure = secureKeyProvider.isEncryptionKeySecure

    @NonNull
    @Throws(Exception::class)
    override fun getCipher(isEncrypt: Boolean): Cipher {
        val secretKey = secureKeyProvider.key
        if (secretKey == null) {
            throw IllegalStateException("Could not retrieve the secret key")
        } else {
            val cipher = Cipher.getInstance(AES_MODE, ENCRYPTION_PROVIDER)
            cipher.init(
                if (isEncrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE,
                secretKey
            )
            return cipher
        }
    }

    companion object {

        private val ENCRYPTION_PROVIDER = "BC"
        private val AES_MODE = "AES/ECB/PKCS7Padding"
    }
}
