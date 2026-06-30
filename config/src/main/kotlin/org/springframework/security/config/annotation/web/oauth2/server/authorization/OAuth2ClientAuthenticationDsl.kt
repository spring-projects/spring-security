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

package org.springframework.security.config.annotation.web.oauth2.server.authorization

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2ClientAuthenticationConfigurer
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import java.util.function.Consumer

/**
 * A Kotlin DSL to configure OAuth 2.0 Client Authentication using idiomatic Kotlin code.
 *
 * @author Mehrdad Bozorgmehr
 * @since 7.0
 */
@OAuth2AuthorizationServerSecurityMarker
class OAuth2ClientAuthenticationDsl {

    var authenticationConverter: AuthenticationConverter? = null
    var authenticationConverters: Consumer<MutableList<AuthenticationConverter>>? = null
    var authenticationProvider: AuthenticationProvider? = null
    var authenticationProviders: Consumer<MutableList<AuthenticationProvider>>? = null
    var authenticationSuccessHandler: AuthenticationSuccessHandler? = null
    var errorResponseHandler: AuthenticationFailureHandler? = null

    internal fun get(): (OAuth2ClientAuthenticationConfigurer) -> Unit {
        return { clientAuthentication ->
            authenticationConverter?.also { clientAuthentication.authenticationConverter(it) }
            authenticationConverters?.also { clientAuthentication.authenticationConverters(it) }
            authenticationProvider?.also { clientAuthentication.authenticationProvider(it) }
            authenticationProviders?.also { clientAuthentication.authenticationProviders(it) }
            authenticationSuccessHandler?.also { clientAuthentication.authenticationSuccessHandler(it) }
            errorResponseHandler?.also { clientAuthentication.errorResponseHandler(it) }
        }
    }
}

