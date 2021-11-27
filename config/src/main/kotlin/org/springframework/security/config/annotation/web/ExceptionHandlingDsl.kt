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

package org.springframework.security.config.annotation.web

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.security.web.util.matcher.RequestMatcher
import java.util.*

/**
 * A Kotlin DSL to configure [HttpSecurity] exception handling using idiomatic Kotlin
 * code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property accessDeniedPage the URL to the access denied page
 * @property accessDeniedHandler the [AccessDeniedHandler] to use
 * @property authenticationEntryPoint the [AuthenticationEntryPoint] to use
 */
@SecurityMarker
class ExceptionHandlingDsl {
    var accessDeniedPage: String? = null
    var accessDeniedHandler: AccessDeniedHandler? = null
    var authenticationEntryPoint: AuthenticationEntryPoint? = null

    private var defaultDeniedHandlerMappings: LinkedHashMap<RequestMatcher, AccessDeniedHandler> = linkedMapOf()
    private var defaultEntryPointMappings: LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> = linkedMapOf()
    private var disabled = false

    /**
     * Sets a default [AccessDeniedHandler] to be used which prefers being
     * invoked for the provided [RequestMatcher].
     *
     * @param deniedHandler the [AccessDeniedHandler] to use
     * @param preferredMatcher the [RequestMatcher] for this default
     * [AccessDeniedHandler]
     */
    fun defaultAccessDeniedHandlerFor(deniedHandler: AccessDeniedHandler, preferredMatcher: RequestMatcher) {
        defaultDeniedHandlerMappings[preferredMatcher] = deniedHandler
    }

    /**
     * Sets a default [AuthenticationEntryPoint] to be used which prefers being
     * invoked for the provided [RequestMatcher].
     *
     * @param entryPoint the [AuthenticationEntryPoint] to use
     * @param preferredMatcher the [RequestMatcher] for this default
     * [AccessDeniedHandler]
     */
    fun defaultAuthenticationEntryPointFor(entryPoint: AuthenticationEntryPoint, preferredMatcher: RequestMatcher) {
        defaultEntryPointMappings[preferredMatcher] = entryPoint
    }

    /**
     * Disable exception handling.
     */
    fun disable() {
        disabled = true
    }

    internal fun get(): (ExceptionHandlingConfigurer<HttpSecurity>) -> Unit {
        return { exceptionHandling ->
            accessDeniedPage?.also { exceptionHandling.accessDeniedPage(accessDeniedPage) }
            accessDeniedHandler?.also { exceptionHandling.accessDeniedHandler(accessDeniedHandler) }
            authenticationEntryPoint?.also { exceptionHandling.authenticationEntryPoint(authenticationEntryPoint) }
            defaultDeniedHandlerMappings.forEach { (matcher, handler) ->
                exceptionHandling.defaultAccessDeniedHandlerFor(handler, matcher)
            }
            defaultEntryPointMappings.forEach { (matcher, entryPoint) ->
                exceptionHandling.defaultAuthenticationEntryPointFor(entryPoint, matcher)
            }
            if (disabled) {
                exceptionHandling.disable()
            }
        }
    }
}
