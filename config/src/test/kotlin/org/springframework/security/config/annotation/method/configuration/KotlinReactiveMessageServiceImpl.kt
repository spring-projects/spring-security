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

import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import org.springframework.security.access.prepost.PostAuthorize
import org.springframework.security.access.prepost.PreAuthorize

class KotlinReactiveMessageServiceImpl : KotlinReactiveMessageService {

    override suspend fun suspendingNoAuth(): String {
        delay(1)
        return "success"
    }

    @PreAuthorize("hasRole('ADMIN')")
    override suspend fun suspendingPreAuthorizeHasRole(): String {
        delay(1)
        return "admin"
    }

    @PreAuthorize("@authz.check(#id)")
    override suspend fun suspendingPreAuthorizeBean(id: Boolean): String {
        delay(1)
        return "check"
    }

    @PostAuthorize("returnObject?.contains(authentication?.name)")
    override suspend fun suspendingPostAuthorizeContainsName(): String {
        delay(1)
        return "user"
    }

    @PreAuthorize("hasRole('ADMIN')")
    override suspend fun suspendingFlowPreAuthorize(): Flow<Int> {
        delay(1)
        return flow {
            for (i in 1..3) {
                delay(1)
                emit(i)
            }
        }
    }

    @PostAuthorize("@authz.check(#id)")
    override suspend fun suspendingFlowPostAuthorize(id: Boolean): Flow<Int> {
        delay(1)
        return flow {
            for (i in 1..3) {
                delay(1)
                emit(i)
            }
        }
    }

    @PreAuthorize("hasRole('ADMIN')")
    override fun flowPreAuthorize(): Flow<Int> {
        return flow {
            for (i in 1..3) {
                delay(1)
                emit(i)
            }
        }
    }

    @PostAuthorize("@authz.check(#id)")
    override fun flowPostAuthorize(id: Boolean): Flow<Int> {
        return flow {
            for (i in 1..3) {
                delay(1)
                emit(i)
            }
        }
    }
}
