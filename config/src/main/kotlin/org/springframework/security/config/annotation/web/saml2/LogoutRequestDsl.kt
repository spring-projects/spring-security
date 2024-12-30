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

package org.springframework.security.config.annotation.web.saml2

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.saml2.Saml2LogoutConfigurer
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidator
import org.springframework.security.saml2.provider.service.web.authentication.logout.HttpSessionLogoutRequestRepository
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestRepository
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestResolver

/**
 * A Kotlin DSL to configure SAML 2.0 Logout Request components using idiomatic Kotlin code.
 *
 * @author Josh Cummings
 * @since 6.3
 * @property logoutUrl The URL by which the asserting party can send a SAML 2.0 Logout Request.
 * The Asserting Party should use whatever HTTP method specified in {@link RelyingPartyRegistration#getSingleLogoutServiceBindings()}.
 * @property logoutRequestValidator the [Saml2LogoutRequestValidator] to use for validating incoming {@code LogoutRequest}s.
 * @property logoutRequestResolver the [Saml2LogoutRequestResolver] to use for generating outgoing {@code LogoutRequest}s.
 * @property logoutRequestRepository the [Saml2LogoutRequestRepository] to use for storing outgoing {@code LogoutRequest}s for
 * linking to the corresponding {@code LogoutResponse} from the asserting party
 */
@Saml2SecurityMarker
class LogoutRequestDsl {
    var logoutUrl = "/logout/saml2/slo"
    var logoutRequestValidator: Saml2LogoutRequestValidator? = null
    var logoutRequestResolver: Saml2LogoutRequestResolver? = null
    var logoutRequestRepository: Saml2LogoutRequestRepository = HttpSessionLogoutRequestRepository()

    internal fun get(): (Saml2LogoutConfigurer<HttpSecurity>.LogoutRequestConfigurer) -> Unit {
        return { logoutRequest ->
            logoutUrl.also { logoutRequest.logoutUrl(logoutUrl) }
            logoutRequestValidator?.also { logoutRequest.logoutRequestValidator(logoutRequestValidator) }
            logoutRequestResolver?.also { logoutRequest.logoutRequestResolver(logoutRequestResolver) }
            logoutRequestRepository.also { logoutRequest.logoutRequestRepository(logoutRequestRepository) }
        }
    }
}
