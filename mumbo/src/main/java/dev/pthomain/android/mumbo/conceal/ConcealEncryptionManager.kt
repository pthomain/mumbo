/*
 *
 * Copyright (C) 2017 Pierre Thomain
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
 *
 */

package dev.pthomain.android.mumbo.conceal

import android.content.Context
import com.facebook.crypto.keychain.KeyChain
import com.facebook.android.crypto.keychain.AndroidConceal
import com.facebook.crypto.Crypto
import com.facebook.crypto.Entity
import com.facebook.soloader.SoLoader
import dev.pthomain.android.boilerplate.core.utils.log.Logger
import dev.pthomain.android.mumbo.base.BaseEncryptionManager
import dev.pthomain.android.mumbo.base.EncryptionManager.KeyPolicy.SHARED_PREFERENCES

internal class ConcealEncryptionManager(
    context: Context,
    logger: Logger,
    keyChain: KeyChain,
    androidConceal: AndroidConceal
) : BaseEncryptionManager(logger, SHARED_PREFERENCES) {

    override val isEncryptionAvailable: Boolean

    private lateinit var crypto: Crypto

    init {
        var isEncryptionAvailable: Boolean
        try {
            SoLoader.init(context, false)
            crypto = androidConceal.createDefaultCrypto(keyChain)

            // Check for whether the crypto functionality is available
            // This might fail if Android does not load libraries correctly.
            isEncryptionAvailable = crypto.isAvailable
        } catch (e: Exception) {
            isEncryptionAvailable = false
        }

        this.isEncryptionAvailable = isEncryptionAvailable
        logger.d(this, "Conceal is" + (if (isEncryptionAvailable) "" else " NOT") + " available")
    }

    override fun encryptBytes(
        toEncrypt: ByteArray?,
        dataTag: String,
        password: String?
    ) =
        if (toEncrypt != null && isEncryptionAvailable) {
            try {
                crypto.encrypt(
                    toEncrypt,
                    Entity.create(dataTag)
                )
            } catch (e: Exception) {
                logger.e(this, e, "Could not encrypt the given bytes")
                null
            }
        } else null

    override fun decryptBytes(
        toDecrypt: ByteArray?,
        dataTag: String,
        password: String?
    ) =
        if (toDecrypt != null && isEncryptionAvailable) {
            try {
                crypto.decrypt(
                    toDecrypt,
                    Entity.create(dataTag)
                )
            } catch (e: Exception) {
                logger.e(this, e, "Could not decrypt the given bytes")
                null
            }
        } else null

}
