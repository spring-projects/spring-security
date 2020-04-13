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

import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.context.ReactorContextWebFilter
import org.springframework.security.web.server.context.ServerSecurityContextRepository

/**
 * A Kotlin DSL to configure [ServerHttpSecurity] basic authorization using idiomatic
 * Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.4
 * @property authenticationManager the [ReactiveAuthenticationManager] used to authenticate.
 * @property securityContextRepository the [ServerSecurityContextRepository] used to save
 * the [Authentication]. For the [SecurityContext] to be loaded on subsequent requests the
 * [ReactorContextWebFilter] must be configured to be able to load the value (they are not
 * implicitly linked).
 * @property authenticationEntryPoint the [ServerAuthenticationEntryPoint] to be
 * populated on [BasicAuthenticationFilter] in the event that authentication fails.
 */
@ServerSecurityMarker
class ServerHttpBasicDsl {
    var authenticationManager: ReactiveAuthenticationManager? = null
    var securityContextRepository: ServerSecurityContextRepository? = null
    var authenticationEntryPoint: ServerAuthenticationEntryPoint? = null

    private var disabled = false

    /**
     * Disables HTTP basic authentication
     */
    fun disable() {
        disabled = true
    }

    internal fun get(): (ServerHttpSecurity.HttpBasicSpec) -> Unit {
        return { httpBasic ->
            authenticationManager?.also { httpBasic.authenticationManager(authenticationManager) }
            securityContextRepository?.also { httpBasic.securityContextRepository(securityContextRepository) }
            authenticationEntryPoint?.also { httpBasic.authenticationEntryPoint(authenticationEntryPoint) }
            if (disabled) {
                httpBasic.disable()
            }
        }
    }
}
