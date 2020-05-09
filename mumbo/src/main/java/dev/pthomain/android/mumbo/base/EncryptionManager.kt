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

package dev.pthomain.android.mumbo.base

interface EncryptionManager {

    val isEncryptionAvailable: Boolean
    val keyPolicy: KeyPolicy

    fun encrypt(
        toEncrypt: String?,
        dataTag: String,
        password: String? = null
    ): String?

    fun encryptBytes(
        toEncrypt: ByteArray?,
        dataTag: String,
        password: String? = null
    ): ByteArray?

    fun decrypt(
        toDecrypt: String?,
        dataTag: String,
        password: String? = null
    ): String?

    fun decryptBytes(
        toDecrypt: ByteArray?,
        dataTag: String,
        password: String? = null
    ): ByteArray?

    enum class KeyPolicy{
        SHARED_PREFERENCES, //key stored in the Android SharedPreferences
        KEY_STORE,          //key stored in the Android KeyStore (might get erased if the user changes their lock screen mechanism)
        KEY_CHAIN,          //key stored in the Android KeyChain (won't get erased if the user changes their lock screen mechanism)
        PROVIDED,            //key provided at runtime by the caller
        JETPACK            //using AndroidX KeySet management
    }
}
