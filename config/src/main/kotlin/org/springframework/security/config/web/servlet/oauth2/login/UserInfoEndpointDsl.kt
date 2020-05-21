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

package org.springframework.security.config.web.servlet.oauth2.login

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.core.user.OAuth2User

/**
 * A Kotlin DSL to configure the Authorization Server's UserInfo Endpoint using
 * idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property userService the OAuth 2.0 service used for obtaining the user attributes of the End-User
 * from the UserInfo Endpoint.
 * @property oidcUserService the OpenID Connect 1.0 service used for obtaining the user attributes of the
 * End-User from the UserInfo Endpoint.
 * @property userAuthoritiesMapper the [GrantedAuthoritiesMapper] used for mapping [OAuth2User.getAuthorities]
 */
@OAuth2LoginSecurityMarker
class UserInfoEndpointDsl {
    var userService: OAuth2UserService<OAuth2UserRequest, OAuth2User>? = null
    var oidcUserService: OAuth2UserService<OidcUserRequest, OidcUser>? = null
    var userAuthoritiesMapper: GrantedAuthoritiesMapper? = null

    private var customUserTypePair: Pair<Class<out OAuth2User>, String>? = null

    /**
     * Sets a custom [OAuth2User] type and associates it to the provided
     * client [ClientRegistration.getRegistrationId] registration identifier.
     *
     * @param customUserType a custom [OAuth2User] type
     * @param clientRegistrationId the client registration identifier
     */
    fun customUserType(customUserType: Class<out OAuth2User>, clientRegistrationId: String) {
        customUserTypePair = Pair(customUserType, clientRegistrationId)
    }

    internal fun get(): (OAuth2LoginConfigurer<HttpSecurity>.UserInfoEndpointConfig) -> Unit {
        return { userInfoEndpoint ->
            userService?.also { userInfoEndpoint.userService(userService) }
            oidcUserService?.also { userInfoEndpoint.oidcUserService(oidcUserService) }
            userAuthoritiesMapper?.also { userInfoEndpoint.userAuthoritiesMapper(userAuthoritiesMapper) }
            customUserTypePair?.also { userInfoEndpoint.customUserType(customUserTypePair!!.first, customUserTypePair!!.second) }
        }
    }
}
