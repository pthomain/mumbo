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

import uk.co.glass_software.android.boilerplate.Boilerplate.logger
import uk.co.glass_software.android.boilerplate.utils.log.Logger
import uk.co.glass_software.android.mumbo.base.BaseEncryptionManager
import javax.crypto.Cipher
import kotlin.math.log

internal abstract class BaseJumboEncryptionManager protected constructor(logger: Logger) :
    BaseEncryptionManager(logger) {

    override fun encryptBytes(
        toEncrypt: ByteArray?,
        dataTag: String
    ) =
        if (toEncrypt == null) null
        else try {
            getCipher(true).doFinal(toEncrypt)
        } catch (e: Exception) {
            logger.e(this, e, "Could not encrypt the given bytes")
            null
        }

    override fun decryptBytes(
        toDecrypt: ByteArray?,
        dataTag: String
    ) =
        if (toDecrypt == null) null
        else try {
            getCipher(false).doFinal(toDecrypt)
        } catch (e: Exception) {
            logger.e(this, e, "Could not decrypt the given bytes")
            null
        }

    @Throws(Exception::class)
    protected abstract fun getCipher(isEncrypt: Boolean): Cipher
}
