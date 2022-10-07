/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy
import org.springframework.security.web.csrf.CsrfTokenRepository
import org.springframework.security.web.csrf.CsrfTokenRequestHandler
import org.springframework.security.web.util.matcher.RequestMatcher

/**
 * A Kotlin DSL to configure [HttpSecurity] CSRF protection
 * using idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property csrfTokenRepository the [CsrfTokenRepository] to use.
 * @property requireCsrfProtectionMatcher specify the [RequestMatcher] to use for
 * determining when CSRF should be applied.
 * @property sessionAuthenticationStrategy the [SessionAuthenticationStrategy] to use.
 * @property csrfTokenRequestHandler the [CsrfTokenRequestHandler] to use for making
 * the CSRF token available as a request attribute
 */
@SecurityMarker
class CsrfDsl {
    var csrfTokenRepository: CsrfTokenRepository? = null
    var requireCsrfProtectionMatcher: RequestMatcher? = null
    var sessionAuthenticationStrategy: SessionAuthenticationStrategy? = null
    var csrfTokenRequestHandler: CsrfTokenRequestHandler? = null

    private var ignoringRequestMatchers: Array<out RequestMatcher>? = null
    private var ignoringRequestMatchersPatterns: Array<out String>? = null
    private var disabled = false

    /**
     * Allows specifying [HttpServletRequest]s that should not use CSRF Protection
     * even if they match the [requireCsrfProtectionMatcher].
     *
     * @param requestMatchers the request matchers that should not use CSRF
     * protection
     */
    fun ignoringRequestMatchers(vararg requestMatchers: RequestMatcher) {
        ignoringRequestMatchers = requestMatchers
    }

    /**
     * Allows specifying [HttpServletRequest]s that should not use CSRF Protection
     * even if they match the [requireCsrfProtectionMatcher].
     *
     * @param patterns the patterns that should not use CSRF protection
     */
    fun ignoringRequestMatchers(vararg patterns: String) {
        ignoringRequestMatchersPatterns = patterns
    }

    /**
     * Disable CSRF protection
     */
    fun disable() {
        disabled = true
    }

    internal fun get(): (CsrfConfigurer<HttpSecurity>) -> Unit {
        return { csrf ->
            csrfTokenRepository?.also { csrf.csrfTokenRepository(csrfTokenRepository) }
            requireCsrfProtectionMatcher?.also { csrf.requireCsrfProtectionMatcher(requireCsrfProtectionMatcher) }
            sessionAuthenticationStrategy?.also { csrf.sessionAuthenticationStrategy(sessionAuthenticationStrategy) }
            csrfTokenRequestHandler?.also { csrf.csrfTokenRequestHandler(csrfTokenRequestHandler) }
            ignoringRequestMatchers?.also { csrf.ignoringRequestMatchers(*ignoringRequestMatchers!!) }
            ignoringRequestMatchersPatterns?.also { csrf.ignoringRequestMatchers(*ignoringRequestMatchersPatterns!!) }
            if (disabled) {
                csrf.disable()
            }
        }
    }
}
