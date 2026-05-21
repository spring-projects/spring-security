/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.config.annotation.web.oauth2.resourceserver

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.oauth2.server.resource.authentication.DPoPAuthenticationToken
import org.springframework.security.oauth2.server.resource.web.DPoPAuthenticationEntryPoint
import org.springframework.security.oauth2.server.resource.web.authentication.DPoPAuthenticationConverter
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.util.matcher.RequestMatcher

/**
 * A Kotlin DSL to configure DPoP-bound access token support using idiomatic Kotlin code.
 *
 * @author Max Batischev
 * @property requestMatcher the [RequestMatcher] used when matching the [HttpServletRequest] to a DPoP-protected resource request.
 * @property authenticationConverter the [AuthenticationConverter] used when attempting to extract a DPoP-bound access token
 * from [HttpServletRequest] to an instance of [DPoPAuthenticationToken] used for authenticating the DPoP-protected resource request.
 * The default is [DPoPAuthenticationConverter].
 * @property authenticationSuccessHandler the [AuthenticationSuccessHandler] used for handling an authenticated DPoP-protected resource request.
 * @property authenticationFailureHandler the [AuthenticationFailureHandler] used for handling a failed DPoP-protected resource request.
 * The default is [AuthenticationEntryPointFailureHandler] with [DPoPAuthenticationEntryPoint].
 * @since 7.1
 */
@OAuth2ResourceServerSecurityMarker
class DPoPDsl {
    var requestMatcher: RequestMatcher? = null
    var authenticationConverter: AuthenticationConverter? = null
    var authenticationSuccessHandler: AuthenticationSuccessHandler? = null
    var authenticationFailureHandler: AuthenticationFailureHandler? = null

    internal fun get(): (OAuth2ResourceServerConfigurer<HttpSecurity>.DPoPConfigurer) -> Unit {
        return { dPoP ->
            requestMatcher?.also { dPoP.requestMatcher(requestMatcher) }
            authenticationConverter?.also { dPoP.authenticationConverter(authenticationConverter) }
            authenticationSuccessHandler?.also { dPoP.authenticationSuccessHandler(authenticationSuccessHandler) }
            authenticationFailureHandler?.also { dPoP.authenticationFailureHandler(authenticationFailureHandler) }
        }
    }
}
