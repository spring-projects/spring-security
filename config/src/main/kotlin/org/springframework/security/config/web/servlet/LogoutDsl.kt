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

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer
import org.springframework.security.core.Authentication
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.util.matcher.RequestMatcher
import java.util.*
import javax.servlet.http.HttpSession

/**
 * A Kotlin DSL to configure [HttpSecurity] logout support
 * using idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property clearAuthentication whether the [SecurityContextLogoutHandler] should clear
 * the [Authentication] at the time of logout.
 * @property clearAuthentication whether to invalidate the [HttpSession] at the time of logout.
 * @property logoutUrl the URL that triggers log out to occur.
 * @property logoutRequestMatcher the [RequestMatcher] that triggers log out to occur.
 * @property logoutSuccessUrl the URL to redirect to after logout has occurred.
 * @property logoutSuccessHandler the [LogoutSuccessHandler] to use after logout has occurred.
 * If this is specified, [logoutSuccessUrl] is ignored.
 */
@SecurityMarker
class LogoutDsl {
    var clearAuthentication: Boolean? = null
    var invalidateHttpSession: Boolean? = null
    var logoutUrl: String? = null
    var logoutRequestMatcher: RequestMatcher? = null
    var logoutSuccessUrl: String? = null
    var logoutSuccessHandler: LogoutSuccessHandler? = null
    var permitAll: Boolean? = null

    private var logoutHandlers = mutableListOf<LogoutHandler>()
    private var deleteCookies: Array<out String>? = null
    private var defaultLogoutSuccessHandlerMappings: LinkedHashMap<RequestMatcher, LogoutSuccessHandler> = linkedMapOf()
    private var disabled = false


    /**
     * Adds a [LogoutHandler]. The [SecurityContextLogoutHandler] is added as
     * the last [LogoutHandler] by default.
     *
     * @param logoutHandler the [LogoutHandler] to add
     */
    fun addLogoutHandler(logoutHandler: LogoutHandler) {
        this.logoutHandlers.add(logoutHandler)
    }

    /**
     * Allows specifying the names of cookies to be removed on logout success.
     *
     * @param cookieNamesToClear the names of cookies to be removed on logout success.
     */
    fun deleteCookies(vararg cookieNamesToClear: String) {
        this.deleteCookies = cookieNamesToClear
    }

    /**
     * Sets a default [LogoutSuccessHandler] to be used which prefers being
     * invoked for the provided [RequestMatcher].
     *
     * @param logoutHandler the [LogoutSuccessHandler] to use
     * @param preferredMatcher the [RequestMatcher] for this default
     * [AccessDeniedHandler]
     */
    fun defaultLogoutSuccessHandlerFor(logoutHandler: LogoutSuccessHandler, preferredMatcher: RequestMatcher) {
        defaultLogoutSuccessHandlerMappings[preferredMatcher] = logoutHandler
    }

    /**
     * Disables logout
     */
    fun disable() {
        disabled = true
    }

    /**
     * Grants access to the [logoutSuccessUrl] and the [logoutUrl] for every user.
     */
    fun permitAll() {
        permitAll = true
    }

    internal fun get(): (LogoutConfigurer<HttpSecurity>) -> Unit {
        return { logout ->
            clearAuthentication?.also { logout.clearAuthentication(clearAuthentication!!) }
            invalidateHttpSession?.also { logout.invalidateHttpSession(invalidateHttpSession!!) }
            logoutUrl?.also { logout.logoutUrl(logoutUrl) }
            logoutRequestMatcher?.also { logout.logoutRequestMatcher(logoutRequestMatcher) }
            logoutSuccessUrl?.also { logout.logoutSuccessUrl(logoutSuccessUrl) }
            logoutSuccessHandler?.also { logout.logoutSuccessHandler(logoutSuccessHandler) }
            deleteCookies?.also { logout.deleteCookies(*deleteCookies!!) }
            permitAll?.also { logout.permitAll(permitAll!!) }
            defaultLogoutSuccessHandlerMappings.forEach { (matcher, handler) ->
                logout.defaultLogoutSuccessHandlerFor(handler, matcher)
            }
            logoutHandlers.forEach { logoutHandler ->
                logout.addLogoutHandler(logoutHandler)
            }
            if (disabled) {
                logout.disable()
            }
        }
    }
}
