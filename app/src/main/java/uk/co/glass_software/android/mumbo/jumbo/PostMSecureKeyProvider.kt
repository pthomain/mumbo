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
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProperties.*
import uk.co.glass_software.android.boilerplate.utils.log.Logger
import uk.co.glass_software.android.mumbo.jumbo.key.KeyModule.Companion.ANDROID_KEY_STORE
import java.security.Key
import java.security.KeyStore
import javax.crypto.KeyGenerator

class PostMSecureKeyProvider internal constructor(
    private val keyStore: KeyStore?,
    private val logger: Logger,
    private val keyAlias: String
) : SecureKeyProvider {

    override val key: Key? = keyStore?.getKey(keyAlias, null)

    override val isEncryptionSupported = keyStore != null

    override val isEncryptionKeySecure = isEncryptionSupported

    init {
        createNewKeyPairIfNeeded()
    }

    @TargetApi(M)
    @Synchronized
    override fun createNewKeyPairIfNeeded() {
        try {
            if (keyStore != null && !keyStore.containsAlias(keyAlias)) {
                KeyGenParameterSpec.Builder(
                    keyAlias,
                    PURPOSE_ENCRYPT or PURPOSE_DECRYPT
                ).apply {
                    setBlockModes(BLOCK_MODE_GCM)
                    setEncryptionPaddings(ENCRYPTION_PADDING_NONE)
                    setRandomizedEncryptionRequired(false)
                }.apply {
                    KeyGenerator.getInstance(
                        KEY_ALGORITHM_AES,
                        ANDROID_KEY_STORE
                    ).apply {
                        init(build())
                        generateKey()
                    }
                }
            }

            if (!keyStore!!.containsAlias(keyAlias))
                throw IllegalStateException("Key pair was not generated")
        } catch (e: Exception) {
            logger.e(this, e, "Could not create a new key")
        }
    }
}
