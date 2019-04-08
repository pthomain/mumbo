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

import android.content.Context

import java.security.KeyStore

import javax.inject.Named
import javax.inject.Singleton

import dagger.Module
import dagger.Provides

import android.os.Build.VERSION.SDK_INT
import android.os.Build.VERSION_CODES.JELLY_BEAN_MR2
import android.os.Build.VERSION_CODES.M
import uk.co.glass_software.android.boilerplate.core.utils.log.Logger
import uk.co.glass_software.android.mumbo.jumbo.key.KeyModule
import uk.co.glass_software.android.mumbo.jumbo.key.KeyModule.Companion.KEY_ALIAS_POST_M
import uk.co.glass_software.android.mumbo.jumbo.key.KeyModule.Companion.KEY_ALIAS_PRE_M
import uk.co.glass_software.android.mumbo.jumbo.key.provider.post_m.PostMSecureKeyProvider
import uk.co.glass_software.android.mumbo.jumbo.key.provider.pre_m.PreMSecureKeyProvider
import uk.co.glass_software.android.mumbo.jumbo.key.provider.pre_m.rsa.RsaEncryptedKeyPairProvider

@Module(includes = [KeyModule::class])
internal class CustomModule {

    @Provides
    @Singleton
    internal fun providePreMSecureKeyProvider(
        keyPairProvider: RsaEncryptedKeyPairProvider,
        context: Context,
        keyStore: KeyStore?,
        logger: Logger,
        @Named(KEY_ALIAS_PRE_M) keyAlias: String
    ) = PreMSecureKeyProvider(
        keyPairProvider,
        context,
        logger,
        keyStore,
        keyAlias
    )

    @Provides
    @Singleton
    internal fun providePostMSecureKeyProvider(
        keyStore: KeyStore?,
        logger: Logger,
        @Named(KEY_ALIAS_POST_M) keyAlias: String
    ) = PostMSecureKeyProvider(
        keyStore,
        logger,
        keyAlias
    )

    @Provides
    @Singleton
    internal fun providePreMEncryptionManager(
        logger: Logger,
        secureKeyProvider: PreMSecureKeyProvider
    ) = if (SDK_INT >= JELLY_BEAN_MR2) {
        PreMJumboEncryptionManager(
            logger,
            secureKeyProvider
        )
    } else null

    @Provides
    @Singleton
    internal fun providePostMEncryptionManager(
        logger: Logger,
        secureKeyProvider: PostMSecureKeyProvider
    ) = if (SDK_INT >= M) {
        PostMJumboEncryptionManager(
            logger,
            secureKeyProvider
        )
    } else null
}
