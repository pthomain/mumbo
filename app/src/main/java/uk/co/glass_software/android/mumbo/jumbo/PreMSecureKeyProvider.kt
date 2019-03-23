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
import android.content.Context
import android.os.Build.VERSION_CODES.JELLY_BEAN_MR2
import android.security.KeyPairGeneratorSpec
import uk.co.glass_software.android.boilerplate.utils.log.Logger
import uk.co.glass_software.android.mumbo.jumbo.key.KeyModule.Companion.ANDROID_KEY_STORE
import uk.co.glass_software.android.mumbo.jumbo.key.RsaEncryptedKeyPairProvider
import java.math.BigInteger
import java.security.Key
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.util.*
import javax.crypto.spec.SecretKeySpec
import javax.security.auth.x500.X500Principal

class PreMSecureKeyProvider internal constructor(
    private val keyPairProvider: RsaEncryptedKeyPairProvider,
    private val applicationContext: Context,
    private val logger: Logger,
    private val keyStore: KeyStore?,
    private val keyAlias: String
) : SecureKeyProvider {

    override val key = SecretKeySpec(keyPairProvider.cipherKey, KEY_ALGORITHM_AES)

    override val isEncryptionSupported = keyStore != null

    override val isEncryptionKeySecure = isEncryptionSupported

    init {
        createNewKeyPairIfNeeded()
        keyPairProvider.initialise()
    }

    @TargetApi(JELLY_BEAN_MR2)
    @Synchronized
    override fun createNewKeyPairIfNeeded() {
        try {
            if (keyStore != null && !keyStore.containsAlias(keyAlias)) {
                val start = Calendar.getInstance()
                val end = Calendar.getInstance()
                end.add(Calendar.YEAR, 30)

                val spec = KeyPairGeneratorSpec.Builder(applicationContext)
                    .setAlias(keyAlias)
                    .setSubject(X500Principal("CN=$keyAlias"))
                    .setSerialNumber(BigInteger.TEN)
                    .setStartDate(start.time)
                    .setEndDate(end.time)
                    .build()

                val keyPairGenerator = KeyPairGenerator.getInstance(
                    KEY_ALGORITHM_RSA,
                    ANDROID_KEY_STORE
                )

                keyPairGenerator.initialize(spec)
                keyPairGenerator.generateKeyPair()

                if (!keyStore.containsAlias(keyAlias)) {
                    throw IllegalStateException("Key pair was not generated")
                }
            }
        } catch (e: Exception) {
            logger.e(this, e, "Could not create a new key")
        }

    }

    companion object {

        private val KEY_ALGORITHM_RSA = "RSA"
        private val KEY_ALGORITHM_AES = "AES"
    }

}
