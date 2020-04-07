/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.config.web.server

import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler

/**
 * A Kotlin DSL to configure [ServerHttpSecurity] exception handling using idiomatic Kotlin
 * code.
 *
 * @author Eleftheria Stein
 * @since 5.4
 * @property authenticationEntryPoint the [ServerAuthenticationEntryPoint] to use when
 * the application request authentication
 * @property accessDeniedHandler the [ServerAccessDeniedHandler] to use when an
 * authenticated user does not hold a required authority
 */
class ServerExceptionHandlingDsl {
    var authenticationEntryPoint: ServerAuthenticationEntryPoint? = null
    var accessDeniedHandler: ServerAccessDeniedHandler? = null

    internal fun get(): (ServerHttpSecurity.ExceptionHandlingSpec) -> Unit {
        return { exceptionHandling ->
            authenticationEntryPoint?.also { exceptionHandling.authenticationEntryPoint(authenticationEntryPoint) }
            accessDeniedHandler?.also { exceptionHandling.accessDeniedHandler(accessDeniedHandler) }
        }
    }
}
