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

package org.springframework.security.config.web.server

import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.ott.reactive.ReactiveOneTimeTokenService
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.security.web.server.authentication.ott.ServerOneTimeTokenGenerationSuccessHandler
import org.springframework.security.web.server.context.ServerSecurityContextRepository

/**
 * A Kotlin DSL to configure [ServerHttpSecurity] form login using idiomatic Kotlin code.
 *
 * @author Max Batischev
 * @since 6.4
 * @property tokenService configures the [ReactiveOneTimeTokenService] used to generate and consume
 * @property authenticationManager configures the [ReactiveAuthenticationManager] used to generate and consume
 * @property authenticationConverter Use this [ServerAuthenticationConverter] when converting incoming requests to an authentication
 * @property authenticationFailureHandler the [ServerAuthenticationFailureHandler] to use when authentication
 * @property authenticationSuccessHandler the [ServerAuthenticationSuccessHandler] to be used
 * @property defaultSubmitPageUrl sets the URL that the default submit page will be generated
 * @property showDefaultSubmitPage configures whether the default one-time token submit page should be shown
 * @property loginProcessingUrl the URL to process the login request
 * @property tokenGeneratingUrl the URL that a One-Time Token generate request will be processed
 * @property tokenGenerationSuccessHandler the strategy to be used to handle generated one-time tokens
 * @property securityContextRepository the [ServerSecurityContextRepository] used to save the [Authentication]. For the [SecurityContext] to be loaded on subsequent requests the [ReactorContextWebFilter] must be configured to be able to load the value (they are not implicitly linked).
 */
@ServerSecurityMarker
class ServerOneTimeTokenLoginDsl {
    var authenticationManager: ReactiveAuthenticationManager? = null
    var tokenService: ReactiveOneTimeTokenService? = null
    var authenticationConverter: ServerAuthenticationConverter? = null
    var authenticationFailureHandler: ServerAuthenticationFailureHandler? = null
    var authenticationSuccessHandler: ServerAuthenticationSuccessHandler? = null
    var tokenGenerationSuccessHandler: ServerOneTimeTokenGenerationSuccessHandler? = null
    var securityContextRepository: ServerSecurityContextRepository? = null
    var defaultSubmitPageUrl: String? = null
    var loginProcessingUrl: String? = null
    var tokenGeneratingUrl: String? = null
    var showDefaultSubmitPage: Boolean? = true

    internal fun get(): (ServerHttpSecurity.OneTimeTokenLoginSpec) -> Unit {
        return { oneTimeTokenLogin ->
            authenticationManager?.also { oneTimeTokenLogin.authenticationManager(authenticationManager) }
            tokenService?.also { oneTimeTokenLogin.tokenService(tokenService) }
            authenticationConverter?.also { oneTimeTokenLogin.authenticationConverter(authenticationConverter) }
            authenticationFailureHandler?.also {
                oneTimeTokenLogin.authenticationFailureHandler(
                    authenticationFailureHandler
                )
            }
            authenticationSuccessHandler?.also {
                oneTimeTokenLogin.authenticationSuccessHandler(
                    authenticationSuccessHandler
                )
            }
            securityContextRepository?.also { oneTimeTokenLogin.securityContextRepository(securityContextRepository) }
            defaultSubmitPageUrl?.also { oneTimeTokenLogin.defaultSubmitPageUrl(defaultSubmitPageUrl) }
            showDefaultSubmitPage?.also { oneTimeTokenLogin.showDefaultSubmitPage(showDefaultSubmitPage!!) }
            loginProcessingUrl?.also { oneTimeTokenLogin.loginProcessingUrl(loginProcessingUrl) }
            tokenGeneratingUrl?.also { oneTimeTokenLogin.tokenGeneratingUrl(tokenGeneratingUrl) }
            tokenGenerationSuccessHandler?.also {
                oneTimeTokenLogin.tokenGenerationSuccessHandler(
                    tokenGenerationSuccessHandler
                )
            }
        }
    }
}
