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
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.security.web.server.context.ReactorContextWebFilter
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher

/**
 * A Kotlin DSL to configure [ServerHttpSecurity] form login using idiomatic
 * Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.4
 * @property authenticationManager the [ReactiveAuthenticationManager] used to authenticate.
 * @property loginPage the url to redirect to which provides a form to log in (i.e. "/login").
 * If this is customized:
 * - The default log in & log out page are no longer provided
 * - The application must render a log in page at the provided URL
 * - The application must render an authentication error page at the provided URL + "?error"
 * - Authentication will occur for POST to the provided URL
 * @property authenticationEntryPoint configures how to request for authentication.
 * @property requiresAuthenticationMatcher configures when authentication is performed.
 * @property authenticationSuccessHandler the [ServerAuthenticationSuccessHandler] used after
 * authentication success.
 * @property authenticationFailureHandler the [ServerAuthenticationFailureHandler] used to handle
 * a failed authentication.
 * @property securityContextRepository the [ServerSecurityContextRepository] used to save
 * the [Authentication]. For the [SecurityContext] to be loaded on subsequent requests the
 * [ReactorContextWebFilter] must be configured to be able to load the value (they are not
 * implicitly linked).
 */
@ServerSecurityMarker
class ServerFormLoginDsl {
    var authenticationManager: ReactiveAuthenticationManager? = null
    var loginPage: String? = null
    var authenticationEntryPoint: ServerAuthenticationEntryPoint? = null
    var requiresAuthenticationMatcher: ServerWebExchangeMatcher? = null
    var authenticationSuccessHandler: ServerAuthenticationSuccessHandler? = null
    var authenticationFailureHandler: ServerAuthenticationFailureHandler? = null
    var securityContextRepository: ServerSecurityContextRepository? = null

    private var disabled = false

    /**
     * Disables HTTP basic authentication
     */
    fun disable() {
        disabled = true
    }

    internal fun get(): (ServerHttpSecurity.FormLoginSpec) -> Unit {
        return { formLogin ->
            authenticationManager?.also { formLogin.authenticationManager(authenticationManager) }
            loginPage?.also { formLogin.loginPage(loginPage) }
            authenticationEntryPoint?.also { formLogin.authenticationEntryPoint(authenticationEntryPoint) }
            requiresAuthenticationMatcher?.also { formLogin.requiresAuthenticationMatcher(requiresAuthenticationMatcher) }
            authenticationSuccessHandler?.also { formLogin.authenticationSuccessHandler(authenticationSuccessHandler) }
            authenticationFailureHandler?.also { formLogin.authenticationFailureHandler(authenticationFailureHandler) }
            securityContextRepository?.also { formLogin.securityContextRepository(securityContextRepository) }
            if (disabled) {
                formLogin.disable()
            }
        }
    }
}
