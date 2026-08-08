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
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OidcUserInfoEndpointConfigurer
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import java.util.function.Consumer
import java.util.function.Function

/**
 * A Kotlin DSL to configure the OpenID Connect 1.0 UserInfo Endpoint using idiomatic Kotlin code.
 *
 * @author Mehrdad Bozorgmehr
 * @since 7.0
 */
@OAuth2AuthorizationServerSecurityMarker
class OidcUserInfoEndpointDsl {

    var userInfoRequestConverter: AuthenticationConverter? = null
    var userInfoRequestConverters: Consumer<MutableList<AuthenticationConverter>>? = null
    var authenticationProviders: Consumer<MutableList<AuthenticationProvider>>? = null
    var userInfoResponseHandler: AuthenticationSuccessHandler? = null
    var errorResponseHandler: AuthenticationFailureHandler? = null
    var userInfoMapper: Function<OidcUserInfoAuthenticationContext, OidcUserInfo>? = null

    internal fun get(): (OidcUserInfoEndpointConfigurer) -> Unit {
        return { userInfoEndpoint ->
            userInfoRequestConverter?.also { userInfoEndpoint.userInfoRequestConverter(it) }
            userInfoRequestConverters?.also { userInfoEndpoint.userInfoRequestConverters(it) }
            authenticationProviders?.also { userInfoEndpoint.authenticationProviders(it) }
            userInfoResponseHandler?.also { userInfoEndpoint.userInfoResponseHandler(it) }
            errorResponseHandler?.also { userInfoEndpoint.errorResponseHandler(it) }
            userInfoMapper?.also { userInfoEndpoint.userInfoMapper(it) }
        }
    }
}

