/*
 * Copyright 2002-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.annotation.method.configuration

import kotlinx.coroutines.flow.Flow

interface KotlinReactiveMessageService {

    suspend fun suspendingNoAuth(): String

    suspend fun suspendingPreAuthorizeHasRole(): String

    suspend fun suspendingPreAuthorizeBean(id: Boolean): String

    suspend fun suspendingPostAuthorizeContainsName(): String

    suspend fun suspendingFlowPreAuthorize(): Flow<Int>

    suspend fun suspendingFlowPostAuthorize(id: Boolean): Flow<Int>

    fun flowPreAuthorize(): Flow<Int>

    fun flowPostAuthorize(id: Boolean): Flow<Int>
}
