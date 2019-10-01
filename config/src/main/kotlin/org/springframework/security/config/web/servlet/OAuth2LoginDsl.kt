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
import org.springframework.security.config.web.servlet.oauth2.login.AuthorizationEndpointDsl
import org.springframework.security.config.web.servlet.oauth2.login.RedirectionEndpointDsl
import org.springframework.security.config.web.servlet.oauth2.login.TokenEndpointDsl
import org.springframework.security.config.web.servlet.oauth2.login.UserInfoEndpointDsl
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler

/**
 * A Kotlin DSL to configure [HttpSecurity] OAuth 2.0 login using idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property clientRegistrationRepository the repository of client registrations.
 * @property authorizedClientRepository the repository for authorized client(s).
 * @property authorizedClientService the service for authorized client(s).
 * @property loginPage the login page to redirect to if authentication is required (i.e.
 * "/login")
 * @property authenticationSuccessHandler the [AuthenticationSuccessHandler] used after
 * authentication success
 * @property authenticationFailureHandler the [AuthenticationFailureHandler] used after
 * authentication success
 * @property failureUrl the URL to send users if authentication fails
 * @property loginProcessingUrl the URL to validate the credentials
 * @property permitAll whether to grant access to the urls for [failureUrl] as well as
 * for the [HttpSecurityBuilder], the [loginPage] and [loginProcessingUrl] for every user
 */
class OAuth2LoginDsl {
    var clientRegistrationRepository: ClientRegistrationRepository? = null
    var authorizedClientRepository: OAuth2AuthorizedClientRepository? = null
    var authorizedClientService: OAuth2AuthorizedClientService? = null
    var loginPage: String? = null
    var authenticationSuccessHandler: AuthenticationSuccessHandler? = null
    var authenticationFailureHandler: AuthenticationFailureHandler? = null
    var failureUrl: String? = null
    var loginProcessingUrl: String? = null
    var permitAll: Boolean? = null

    private var defaultSuccessUrlOption: Pair<String, Boolean>? = null
    private var authorizationEndpoint: ((OAuth2LoginConfigurer<HttpSecurity>.AuthorizationEndpointConfig) -> Unit)? = null
    private var tokenEndpoint: ((OAuth2LoginConfigurer<HttpSecurity>.TokenEndpointConfig) -> Unit)? = null
    private var redirectionEndpoint: ((OAuth2LoginConfigurer<HttpSecurity>.RedirectionEndpointConfig) -> Unit)? = null
    private var userInfoEndpoint: ((OAuth2LoginConfigurer<HttpSecurity>.UserInfoEndpointConfig) -> Unit)? = null

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

    /**
     * Configures the Authorization Server's Authorization Endpoint.
     *
     * Example:
     *
     * ```
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      httpSecurity(http) {
     *          oauth2Login {
     *              authorizationEndpoint {
     *                  baseUri = "/auth"
     *              }
     *          }
     *      }
     *  }
     * }
     * ```
     *
     * @param authorizationEndpointConfig custom configurations to configure the authorization
     * endpoint
     * @see [AuthorizationEndpointDsl]
     */
    fun authorizationEndpoint(authorizationEndpointConfig: AuthorizationEndpointDsl.() -> Unit) {
        this.authorizationEndpoint = AuthorizationEndpointDsl().apply(authorizationEndpointConfig).get()
    }

    /**
     * Configures the Authorization Server's Token Endpoint.
     *
     * Example:
     *
     * ```
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      httpSecurity(http) {
     *          oauth2Login {
     *              tokenEndpoint {
     *                  accessTokenResponseClient = getAccessTokenResponseClient()
     *              }
     *          }
     *      }
     *  }
     * }
     * ```
     *
     * @param tokenEndpointConfig custom configurations to configure the token
     * endpoint
     * @see [TokenEndpointDsl]
     */
    fun tokenEndpoint(tokenEndpointConfig: TokenEndpointDsl.() -> Unit) {
        this.tokenEndpoint = TokenEndpointDsl().apply(tokenEndpointConfig).get()
    }

    /**
     * Configures the Authorization Server's Redirection Endpoint.
     *
     * Example:
     *
     * ```
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      httpSecurity(http) {
     *          oauth2Login {
     *              redirectionEndpoint {
     *                  baseUri = "/home"
     *              }
     *          }
     *      }
     *  }
     * }
     * ```
     *
     * @param redirectionEndpointConfig custom configurations to configure the redirection
     * endpoint
     * @see [RedirectionEndpointDsl]
     */
    fun redirectionEndpoint(redirectionEndpointConfig: RedirectionEndpointDsl.() -> Unit) {
        this.redirectionEndpoint = RedirectionEndpointDsl().apply(redirectionEndpointConfig).get()
    }

    /**
     * Configures the Authorization Server's UserInfo Endpoint.
     *
     * Example:
     *
     * ```
     * @EnableWebSecurity
     * class SecurityConfig : WebSecurityConfigurerAdapter() {
     *
     *  override fun configure(http: HttpSecurity) {
     *      httpSecurity(http) {
     *          oauth2Login {
     *              userInfoEndpoint {
     *                  userService = getUserService()
     *              }
     *          }
     *      }
     *  }
     * }
     * ```
     *
     * @param userInfoEndpointConfig custom configurations to configure the user info
     * endpoint
     * @see [UserInfoEndpointDsl]
     */
    fun userInfoEndpoint(userInfoEndpointConfig: UserInfoEndpointDsl.() -> Unit) {
        this.userInfoEndpoint = UserInfoEndpointDsl().apply(userInfoEndpointConfig).get()
    }

    internal fun get(): (OAuth2LoginConfigurer<HttpSecurity>) -> Unit {
        return { oauth2Login ->
            clientRegistrationRepository?.also { oauth2Login.clientRegistrationRepository(clientRegistrationRepository) }
            authorizedClientRepository?.also { oauth2Login.authorizedClientRepository(authorizedClientRepository) }
            authorizedClientService?.also { oauth2Login.authorizedClientService(authorizedClientService) }
            loginPage?.also { oauth2Login.loginPage(loginPage) }
            failureUrl?.also { oauth2Login.failureUrl(failureUrl) }
            loginProcessingUrl?.also { oauth2Login.loginProcessingUrl(loginProcessingUrl) }
            permitAll?.also { oauth2Login.permitAll(permitAll!!) }
            defaultSuccessUrlOption?.also {
                oauth2Login.defaultSuccessUrl(defaultSuccessUrlOption!!.first, defaultSuccessUrlOption!!.second)
            }
            authenticationSuccessHandler?.also { oauth2Login.successHandler(authenticationSuccessHandler) }
            authenticationFailureHandler?.also { oauth2Login.failureHandler(authenticationFailureHandler) }
            authorizationEndpoint?.also { oauth2Login.authorizationEndpoint(authorizationEndpoint) }
            tokenEndpoint?.also { oauth2Login.tokenEndpoint(tokenEndpoint) }
            redirectionEndpoint?.also { oauth2Login.redirectionEndpoint(redirectionEndpoint) }
            userInfoEndpoint?.also { oauth2Login.userInfoEndpoint(userInfoEndpoint) }
        }
    }
}
