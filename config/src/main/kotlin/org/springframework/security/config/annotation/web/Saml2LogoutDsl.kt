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

package org.springframework.security.config.annotation.web

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.saml2.Saml2LogoutConfigurer
import org.springframework.security.config.annotation.web.saml2.LogoutRequestDsl
import org.springframework.security.config.annotation.web.saml2.LogoutResponseDsl
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository

/**
 * A Kotlin DSL to configure [HttpSecurity] SAML2 logout using idiomatic Kotlin code.
 *
 * @author Josh Cummings
 * @since 6.3
 * @property relyingPartyRegistrationRepository the [RelyingPartyRegistrationRepository] of relying parties,
 * each party representing a service provider, SP and this host, and identity provider, IDP pair that
 * communicate with each other.
 * @property logoutUrl the logout page to begin the SLO redirect flow
 */
@SecurityMarker
class Saml2LogoutDsl {
    var relyingPartyRegistrationRepository: RelyingPartyRegistrationRepository? = null
    var logoutUrl: String? = null

    private var logoutRequest: ((Saml2LogoutConfigurer<HttpSecurity>.LogoutRequestConfigurer) -> Unit)? = null
    private var logoutResponse: ((Saml2LogoutConfigurer<HttpSecurity>.LogoutResponseConfigurer) -> Unit)? = null

    /**
     * Configures SAML 2.0 Logout Request components
     * @param logoutRequestConfig the {@link Customizer} to provide more
     * options for the {@link LogoutRequestConfigurer}
     */
    fun logoutRequest(logoutRequestConfig: LogoutRequestDsl.() -> Unit) {
        this.logoutRequest = LogoutRequestDsl().apply(logoutRequestConfig).get()
    }

    /**
     * Configures SAML 2.0 Logout Response components
     * @param logoutResponseConfig the {@link Customizer} to provide more
     * options for the {@link LogoutResponseConfigurer}
     */
    fun logoutResponse(logoutResponseConfig: LogoutResponseDsl.() -> Unit) {
        this.logoutResponse = LogoutResponseDsl().apply(logoutResponseConfig).get()
    }

    internal fun get(): (Saml2LogoutConfigurer<HttpSecurity>) -> Unit {
        return { saml2Logout ->
            relyingPartyRegistrationRepository?.also { saml2Logout.relyingPartyRegistrationRepository(relyingPartyRegistrationRepository) }
            logoutUrl?.also { saml2Logout.logoutUrl(logoutUrl) }
            logoutRequest?.also { saml2Logout.logoutRequest(logoutRequest) }
            logoutResponse?.also { saml2Logout.logoutResponse(logoutResponse) }
        }
    }
}
