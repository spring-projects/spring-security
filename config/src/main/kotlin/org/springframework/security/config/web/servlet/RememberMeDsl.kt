/*
 * Copyright 2002-2021 the original author or authors.
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
import org.springframework.security.config.annotation.web.configurers.RememberMeConfigurer
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.RememberMeServices
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository

/**
 * A Kotlin DSL to configure [HttpSecurity] Remember me using idiomatic Kotlin code.
 *
 * @author Ivan Pavlov
 * @property authenticationSuccessHandler the [AuthenticationSuccessHandler] used after
 * authentication success
 * @property key the key to identify tokens
 * @property rememberMeServices the [RememberMeServices] to use
 * @property rememberMeParameter the HTTP parameter used to indicate to remember
 * the user at time of login. Defaults to 'remember-me'
 * @property rememberMeCookieName the name of cookie which store the token for
 * remember me authentication. Defaults to 'remember-me'
 * @property rememberMeCookieDomain the domain name within which the remember me cookie
 * is visible
 * @property tokenRepository the [PersistentTokenRepository] to use. Defaults to
 * [org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices] instead
 * @property userDetailsService the [UserDetailsService] used to look up the UserDetails
 * when a remember me token is valid
 * @property tokenValiditySeconds how long (in seconds) a token is valid for.
 * Defaults to 2 weeks
 * @property useSecureCookie whether the cookie should be flagged as secure or not
 * @property alwaysRemember whether the cookie should always be created even if
 * the remember-me parameter is not set. Defaults to `false`
 */
@SecurityMarker
class RememberMeDsl {
    var authenticationSuccessHandler: AuthenticationSuccessHandler? = null
    var key: String? = null
    var rememberMeServices: RememberMeServices? = null
    var rememberMeParameter: String? = null
    var rememberMeCookieName: String? = null
    var rememberMeCookieDomain: String? = null
    var tokenRepository: PersistentTokenRepository? = null
    var userDetailsService: UserDetailsService? = null
    var tokenValiditySeconds: Int? = null
    var useSecureCookie: Boolean? = null
    var alwaysRemember: Boolean? = null

    internal fun get(): (RememberMeConfigurer<HttpSecurity>) -> Unit {
        return { rememberMe ->
            authenticationSuccessHandler?.also { rememberMe.authenticationSuccessHandler(authenticationSuccessHandler) }
            key?.also { rememberMe.key(key) }
            rememberMeServices?.also { rememberMe.rememberMeServices(rememberMeServices) }
            rememberMeParameter?.also { rememberMe.rememberMeParameter(rememberMeParameter) }
            rememberMeCookieName?.also { rememberMe.rememberMeCookieName(rememberMeCookieName) }
            rememberMeCookieDomain?.also { rememberMe.rememberMeCookieDomain(rememberMeCookieDomain) }
            tokenRepository?.also { rememberMe.tokenRepository(tokenRepository) }
            userDetailsService?.also { rememberMe.userDetailsService(userDetailsService) }
            tokenValiditySeconds?.also { rememberMe.tokenValiditySeconds(tokenValiditySeconds!!) }
            useSecureCookie?.also { rememberMe.useSecureCookie(useSecureCookie!!) }
            alwaysRemember?.also { rememberMe.alwaysRemember(alwaysRemember!!) }
        }
    }
}
