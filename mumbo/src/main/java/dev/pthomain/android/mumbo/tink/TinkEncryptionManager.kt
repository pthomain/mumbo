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

package dev.pthomain.android.mumbo.tink

import android.content.Context
import androidx.annotation.RequiresApi
import androidx.security.crypto.MasterKeys
import com.google.common.base.Charsets.UTF_8
import com.google.crypto.tink.Aead
import com.google.crypto.tink.aead.AeadFactory
import com.google.crypto.tink.aead.AeadKeyTemplates
import com.google.crypto.tink.config.TinkConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import com.google.crypto.tink.subtle.Base64
import dev.pthomain.android.mumbo.base.EncryptionManager
import dev.pthomain.android.mumbo.base.EncryptionManager.KeyPolicy.JETPACK
import java.nio.ByteBuffer
import java.security.GeneralSecurityException

@RequiresApi(23)
internal class TinkEncryptionManager(context: Context) : EncryptionManager {

    companion object {
        private const val SHARED_PREFS_FILE_NAME = "mumbo_tink_shared_prefs"
        private const val VALUE_KEYSET_ALIAS = "__mumbo_tink_value_keyset__"
        private const val KEYSTORE_PATH_URI = "android-keystore://"
        private const val INTEGER_SIZE = 32
        private const val BYTE_SIZE = 8
        private const val INTEGER_BYTES = INTEGER_SIZE / BYTE_SIZE
    }

    private val aead: Aead?
    override val isEncryptionAvailable: Boolean
    override val keyPolicy = JETPACK

    init {
        val isAvailable = try {
            TinkConfig.register()
            true
        } catch (e: Exception) {
            false
        }

        var aead: Aead?

        if (isAvailable) {
            try {
                val keyGenParameterSpec = MasterKeys.AES256_GCM_SPEC
                val masterKeyAlias = MasterKeys.getOrCreate(keyGenParameterSpec)

                val aeadKeysetHandle = AndroidKeysetManager.Builder()
                    .withKeyTemplate(AeadKeyTemplates.AES256_GCM)
                    .withSharedPref(
                        context,
                        VALUE_KEYSET_ALIAS,
                        SHARED_PREFS_FILE_NAME
                    )
                    .withMasterKeyUri(KEYSTORE_PATH_URI + masterKeyAlias)
                    .build().keysetHandle

                aead = AeadFactory.getPrimitive(aeadKeysetHandle)
            } catch (e: Exception) {
                aead = null
            }
        } else {
            aead = null
        }

        this.aead = aead
        isEncryptionAvailable = aead != null
    }

    override fun encrypt(toEncrypt: String?,
                         dataTag: String,
                         password: String?) =
            if (isEncryptionAvailable && toEncrypt != null) {
                Base64.encode(encryptBytes(
                        toEncrypt.toByteArray(UTF_8),
                        dataTag,
                        password
                ))
            } else null

    override fun encryptBytes(toEncrypt: ByteArray?,
                              dataTag: String,
                              password: String?) =
            if (isEncryptionAvailable && toEncrypt != null) {
                val stringByteLength = toEncrypt.size

                val buffer = ByteBuffer.allocate(
                    INTEGER_BYTES + stringByteLength
                )

                buffer.putInt(stringByteLength)
                buffer.put(toEncrypt)

                aead?.encrypt(
                        buffer.array(),
                        dataTag.toByteArray(UTF_8)
                )
            } else null

    override fun decrypt(toDecrypt: String?,
                         dataTag: String,
                         password: String?) =
            try {
                if (isEncryptionAvailable && toDecrypt != null) {
                    val cipherText = Base64.decode(toDecrypt, Base64.DEFAULT)

                    decryptBytesToByteBuffer(cipherText, dataTag).let {
                        UTF_8.decode(it).toString()
                    }
                } else null
            } catch (ex: GeneralSecurityException) {
                throw SecurityException("Could not decrypt value. " + ex.message, ex)
            }

    override fun decryptBytes(toDecrypt: ByteArray?,
                              dataTag: String,
                              password: String?) =
            if (isEncryptionAvailable && toDecrypt != null) {
                decryptBytesToByteBuffer(toDecrypt, dataTag)?.let {
                    ByteArray(it.capacity()).apply {
                        it.get(this)
                    }
                }
            } else null

    private fun decryptBytesToByteBuffer(toDecrypt: ByteArray?,
                                         dataTag: String) =
            if (isEncryptionAvailable && toDecrypt != null) {
                val value = aead?.decrypt(toDecrypt, dataTag.toByteArray(UTF_8))
                val buffer = ByteBuffer.wrap(value)

                buffer.position(0)
                val stringLength = buffer.int
                val stringSlice = buffer.slice()
                buffer.limit(stringLength)
                stringSlice
            } else null

}