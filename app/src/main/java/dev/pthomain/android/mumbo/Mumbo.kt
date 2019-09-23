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

package dev.pthomain.android.mumbo

import android.content.Context
import androidx.annotation.RequiresApi
import dev.pthomain.android.boilerplate.core.utils.log.Logger

class Mumbo(
    context: Context,
    logger: Logger? = null
) {

    fun conceal() = component.conceal()

    @RequiresApi(23)
    fun tink() = component.tink()

    private val component =
        DaggerMumboComponent.builder()
            .mumboModule(
                MumboModule(
                    context,
                    logger ?: noLogger()
                )
            )
            .build()

    private fun noLogger() = object : Logger {
        override fun d(tagOrCaller: Any, message: String) = Unit
        override fun e(tagOrCaller: Any, message: String) = Unit
        override fun e(tagOrCaller: Any, t: Throwable, message: String?) = Unit
    }
}