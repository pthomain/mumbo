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

import android.annotation.TargetApi
import android.os.Build.VERSION_CODES.M
import io.reactivex.annotations.NonNull
import uk.co.glass_software.android.boilerplate.core.utils.log.Logger
import uk.co.glass_software.android.mumbo.base.EncryptionManager.KeyPolicy.KEY_STORE
import uk.co.glass_software.android.mumbo.jumbo.key.provider.SecureKeyProvider
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

internal class PostMJumboEncryptionManager(
    logger: Logger,
    private val secureKeyProvider: SecureKeyProvider
) : BaseJumboEncryptionManager(logger, KEY_STORE) {

    override val isEncryptionAvailable = secureKeyProvider.isEncryptionSupported

    @NonNull
    @TargetApi(M)
    @Throws(Exception::class)
    override fun getCipher(isEncrypt: Boolean,
                           password: String?): Cipher {
        val secretKey = secureKeyProvider.key

        if (secretKey == null) throw IllegalStateException("Could not retrieve the secret key")
        else {
            val cipher = Cipher.getInstance(AES_MODE)
            cipher.init(
                if (isEncrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE,
                secretKey,
                GCMParameterSpec(128, FIXED_IV.toByteArray())
            )
            return cipher
        }
    }

    companion object {
        //see https://medium.com/@ericfu/securely-storing-secrets-in-an-android-application-501f030ae5a3#.qcgaaeaso
        //and https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
        private val FIXED_IV = "ABkbm8HC1ytJ"
        private val AES_MODE = "AES/GCM/NoPadding"
    }
}
