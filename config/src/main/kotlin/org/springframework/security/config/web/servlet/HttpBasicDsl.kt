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

package org.springframework.security.config.web.servlet

import org.springframework.security.authentication.AuthenticationDetailsSource
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import javax.servlet.http.HttpServletRequest

/**
 * A Kotlin DSL to configure [HttpSecurity] basic authentication using idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property realmName the HTTP Basic realm to use. If [authenticationEntryPoint]
 * has been invoked, invoking this method will result in an error.
 * @property authenticationEntryPoint the [AuthenticationEntryPoint] to be populated on
 * [BasicAuthenticationFilter] in the event that authentication fails.
 * @property authenticationDetailsSource the custom [AuthenticationDetailsSource] to use for
 * basic authentication.
 */
class HttpBasicDsl {
    var realmName: String? = null
    var authenticationEntryPoint: AuthenticationEntryPoint? = null
    var authenticationDetailsSource: AuthenticationDetailsSource<HttpServletRequest, *>? = null

    private var disabled = false

    /**
     * Disables HTTP basic authentication
     */
    fun disable() {
        disabled = true
    }

    internal fun get(): (HttpBasicConfigurer<HttpSecurity>) -> Unit {
        return { httpBasic ->
            realmName?.also { httpBasic.realmName(realmName) }
            authenticationEntryPoint?.also { httpBasic.authenticationEntryPoint(authenticationEntryPoint) }
            authenticationDetailsSource?.also { httpBasic.authenticationDetailsSource(authenticationDetailsSource) }
            if (disabled) {
                httpBasic.disable()
            }
        }
    }
}
