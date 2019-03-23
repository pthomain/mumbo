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

import android.content.Context
import android.os.Build.VERSION.SDK_INT
import android.os.Build.VERSION_CODES.JELLY_BEAN_MR2
import com.facebook.crypto.CryptoConfig
import dagger.Module
import dagger.Provides
import uk.co.glass_software.android.boilerplate.Boilerplate
import uk.co.glass_software.android.boilerplate.utils.log.Logger
import uk.co.glass_software.android.boilerplate.utils.preferences.Prefs
import uk.co.glass_software.android.boilerplate.utils.preferences.SharedPrefsDelegate
import java.security.KeyStore
import javax.inject.Named
import javax.inject.Singleton

@Module
internal class KeyModule(
    private val context: Context,
    private val isDebug: Boolean
) {

    private val keyAlias: String = context.applicationContext.packageName + ".JumboKey"

    @Provides
    @Singleton
    internal fun provideKeyStore(logger: Logger) =
        if (SDK_INT < JELLY_BEAN_MR2) null
        else try {
            KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        } catch (e: Exception) {
            logger.e(this, e, "KeyStore could not be loaded")
            null
        }

    @Provides
    @Singleton
    @Named(KEY_ALIAS_PRE_M)
    internal fun provideKeyAliasPreM() = "$keyAlias.preM"

    @Provides
    @Singleton
    @Named(KEY_ALIAS_POST_M)
    internal fun provideKeyAliasPostM() = "$keyAlias.postM"

    @Provides
    @Singleton
    internal fun provideRsaEncrypter(
        keyStore: KeyStore?,
        logger: Logger,
        @Named(KEY_ALIAS_PRE_M) keyAlias: String
    ) = RsaEncrypter(
        keyStore,
        logger,
        keyAlias
    )

    @Provides
    @Singleton
    internal fun provideCryptoConfig() = CryptoConfig.KEY_256

    @Provides
    @Singleton
    internal fun provideKeyPairProvider(
        rsaEncrypter: RsaEncrypter,
        logger: Logger,
        @Named(KEY_PAIR) keyPairPref: SharedPrefsDelegate<String>,
        cryptoConfig: CryptoConfig
    ) = RsaEncryptedKeyPairProvider(
        rsaEncrypter,
        logger,
        keyPairPref,
        cryptoConfig
    )

    @Provides
    @Singleton
    @Named(JUMBO_PREFS)
    internal fun providePrefs() =
        Boilerplate.init(context, isDebug).let { Prefs.with(JUMBO_PREFS) }

    @Provides
    @Singleton
    @Named(KEY_PAIR)
    internal fun provideKeyPairPref(
        @Named(JUMBO_PREFS) prefs: Prefs
    ) = prefs.open<String>(KEY_PAIR)

    companion object {
        const val KEY_ALIAS_PRE_M = "KEY_ALIAS_PRE_M"
        const val KEY_ALIAS_POST_M = "KEY_ALIAS_POST_M"
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val KEY_PAIR = "KEY_PAIR"
        const val JUMBO_PREFS = "JUMBO_PREFS"
    }

}
