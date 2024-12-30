/*
 * Copyright 2002-2024 the original author or authors.
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

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.ott.OneTimeTokenService
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.ott.OneTimeTokenLoginConfigurer
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler

/**
 * A Kotlin DSL to configure [HttpSecurity] OAuth 2.0 login using idiomatic Kotlin code.
 *
 * @author Max Batischev
 * @since 6.4
 * @property tokenService configures the [OneTimeTokenService] used to generate and consume
 * @property authenticationConverter Use this [AuthenticationConverter] when converting incoming requests to an authentication
 * @property authenticationFailureHandler the [AuthenticationFailureHandler] to use when authentication
 * @property authenticationSuccessHandler the [AuthenticationSuccessHandler] to be used
 * @property defaultSubmitPageUrl sets the URL that the default submit page will be generated
 * @property showDefaultSubmitPage configures whether the default one-time token submit page should be shown
 * @property loginProcessingUrl the URL to process the login request
 * @property tokenGeneratingUrl the URL that a One-Time Token generate request will be processed
 * @property oneTimeTokenGenerationSuccessHandler the strategy to be used to handle generated one-time tokens
 * @property authenticationProvider the [AuthenticationProvider] to use when authenticating the user
 */
@SecurityMarker
class OneTimeTokenLoginDsl {
    var tokenService: OneTimeTokenService? = null
    var authenticationConverter: AuthenticationConverter? = null
    var authenticationFailureHandler: AuthenticationFailureHandler? = null
    var authenticationSuccessHandler: AuthenticationSuccessHandler? = null
    var defaultSubmitPageUrl: String? = null
    var loginProcessingUrl: String? = null
    var tokenGeneratingUrl: String? = null
    var showDefaultSubmitPage: Boolean? = true
    var oneTimeTokenGenerationSuccessHandler: OneTimeTokenGenerationSuccessHandler? = null
    var authenticationProvider: AuthenticationProvider? = null

    internal fun get(): (OneTimeTokenLoginConfigurer<HttpSecurity>) -> Unit {
        return { oneTimeTokenLoginConfigurer ->
            tokenService?.also { oneTimeTokenLoginConfigurer.tokenService(tokenService) }
            authenticationConverter?.also { oneTimeTokenLoginConfigurer.authenticationConverter(authenticationConverter) }
            authenticationFailureHandler?.also {
                oneTimeTokenLoginConfigurer.authenticationFailureHandler(
                    authenticationFailureHandler
                )
            }
            authenticationSuccessHandler?.also {
                oneTimeTokenLoginConfigurer.authenticationSuccessHandler(
                    authenticationSuccessHandler
                )
            }
            defaultSubmitPageUrl?.also { oneTimeTokenLoginConfigurer.defaultSubmitPageUrl(defaultSubmitPageUrl) }
            showDefaultSubmitPage?.also { oneTimeTokenLoginConfigurer.showDefaultSubmitPage(showDefaultSubmitPage!!) }
            loginProcessingUrl?.also { oneTimeTokenLoginConfigurer.loginProcessingUrl(loginProcessingUrl) }
            tokenGeneratingUrl?.also { oneTimeTokenLoginConfigurer.tokenGeneratingUrl(tokenGeneratingUrl) }
            oneTimeTokenGenerationSuccessHandler?.also {
                oneTimeTokenLoginConfigurer.tokenGenerationSuccessHandler(
                    oneTimeTokenGenerationSuccessHandler
                )
            }
            authenticationProvider?.also { oneTimeTokenLoginConfigurer.authenticationProvider(authenticationProvider) }
        }
    }
}
