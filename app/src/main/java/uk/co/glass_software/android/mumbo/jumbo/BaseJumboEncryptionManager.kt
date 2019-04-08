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

import uk.co.glass_software.android.boilerplate.core.utils.log.Logger
import uk.co.glass_software.android.mumbo.base.BaseEncryptionManager
import uk.co.glass_software.android.mumbo.base.EncryptionManager.KeyPolicy
import javax.crypto.Cipher

internal abstract class BaseJumboEncryptionManager protected constructor(
    logger: Logger,
    override val keyPolicy: KeyPolicy
) : BaseEncryptionManager(logger, keyPolicy) {

    override fun encryptBytes(
        toEncrypt: ByteArray?,
        dataTag: String,
        password: String?
    ) = encryptOrDecryptBytes(
        toEncrypt,
        dataTag,
        password,
        true
    )

    override fun decryptBytes(
        toDecrypt: ByteArray?,
        dataTag: String,
        password: String?
    ) = encryptOrDecryptBytes(
        toDecrypt,
        dataTag,
        password,
        false
    )

    private fun encryptOrDecryptBytes(
        data: ByteArray?,
        dataTag: String,
        password: String?,
        isEncrypt: Boolean
    ) =
        if (data != null) {
            try {
                getCipher(isEncrypt, password).doFinal(data)
            } catch (e: Exception) {
                logger.e(this, e, "Could not ${if (isEncrypt) "encrypt" else "decrypt"} the given bytes")
                null
            }
        } else null

    @Throws(Exception::class)
    protected abstract fun getCipher(
        isEncrypt: Boolean,
        password: String?
    ): Cipher

}
