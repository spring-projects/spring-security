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

import org.springframework.security.config.annotation.web.HttpSecurityBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler

/**
 * A Kotlin DSL to configure [HttpSecurity] form login using idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property loginPage the login page to redirect to if authentication is required (i.e.
 * "/login")
 * @property authenticationSuccessHandler the [AuthenticationSuccessHandler] used after
 * authentication success
 * @property authenticationFailureHandler the [AuthenticationFailureHandler] used after
 * authentication failure
 * @property failureUrl the URL to send users if authentication fails
 * @property loginProcessingUrl the URL to validate the credentials
 * @property permitAll whether to grant access to the urls for [failureUrl] as well as
 * for the [HttpSecurityBuilder], the [loginPage] and [loginProcessingUrl] for every user
 */
@SecurityMarker
class FormLoginDsl {
    var loginPage: String? = null
    var authenticationSuccessHandler: AuthenticationSuccessHandler? = null
    var authenticationFailureHandler: AuthenticationFailureHandler? = null
    var failureUrl: String? = null
    var loginProcessingUrl: String? = null
    var permitAll: Boolean? = null

    private var defaultSuccessUrlOption: Pair<String, Boolean>? = null

    /**
     * Grants access to the urls for [failureUrl] as well as for the [HttpSecurityBuilder], the
     * [loginPage] and [loginProcessingUrl] for every user.
     */
    fun permitAll() {
        permitAll = true
    }

    /**
     * Specifies where users will be redirected after authenticating successfully if
     * they have not visited a secured page prior to authenticating or [alwaysUse]
     * is true.
     *
     * @param defaultSuccessUrl the default success url
     * @param alwaysUse true if the [defaultSuccessUrl] should be used after
     * authentication despite if a protected page had been previously visited
     */
    fun defaultSuccessUrl(defaultSuccessUrl: String, alwaysUse: Boolean) {
        defaultSuccessUrlOption = Pair(defaultSuccessUrl, alwaysUse)
    }

    internal fun get(): (FormLoginConfigurer<HttpSecurity>) -> Unit {
        return { login ->
            loginPage?.also { login.loginPage(loginPage) }
            failureUrl?.also { login.failureUrl(failureUrl) }
            loginProcessingUrl?.also { login.loginProcessingUrl(loginProcessingUrl) }
            permitAll?.also { login.permitAll(permitAll!!) }
            defaultSuccessUrlOption?.also {
                login.defaultSuccessUrl(defaultSuccessUrlOption!!.first, defaultSuccessUrlOption!!.second)
            }
            authenticationSuccessHandler?.also { login.successHandler(authenticationSuccessHandler) }
            authenticationFailureHandler?.also { login.failureHandler(authenticationFailureHandler) }
        }
    }
}
