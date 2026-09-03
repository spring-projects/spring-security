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
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OidcLogoutEndpointConfigurer
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import java.util.function.Consumer

/**
 * A Kotlin DSL to configure the OpenID Connect 1.0 RP-Initiated Logout Endpoint using idiomatic Kotlin code.
 *
 * @author Mehrdad Bozorgmehr
 * @since 7.0
 */
@OAuth2AuthorizationServerSecurityMarker
class OidcLogoutEndpointDsl {

    var logoutRequestConverter: AuthenticationConverter? = null
    var logoutRequestConverters: Consumer<MutableList<AuthenticationConverter>>? = null
    var authenticationProviders: Consumer<MutableList<AuthenticationProvider>>? = null
    var logoutResponseHandler: AuthenticationSuccessHandler? = null
    var errorResponseHandler: AuthenticationFailureHandler? = null

    internal fun get(): (OidcLogoutEndpointConfigurer) -> Unit {
        return { logoutEndpoint ->
            logoutRequestConverter?.also { logoutEndpoint.logoutRequestConverter(it) }
            logoutRequestConverters?.also { logoutEndpoint.logoutRequestConverters(it) }
            authenticationProviders?.also { logoutEndpoint.authenticationProviders(it) }
            logoutResponseHandler?.also { logoutEndpoint.logoutResponseHandler(it) }
            errorResponseHandler?.also { logoutEndpoint.errorResponseHandler(it) }
        }
    }
}

