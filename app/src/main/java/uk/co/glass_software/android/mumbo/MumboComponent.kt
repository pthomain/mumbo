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

package uk.co.glass_software.android.mumbo

import dagger.Component
import uk.co.glass_software.android.mumbo.base.EncryptionManager
import javax.inject.Named
import javax.inject.Singleton

@Singleton
@Component(modules = [MumboModule::class])
internal interface MumboComponent {

   @Named(CONCEAL)
   fun conceal(): EncryptionManager

    companion object {
        const val CONCEAL = "CONCEAL"
    }
}