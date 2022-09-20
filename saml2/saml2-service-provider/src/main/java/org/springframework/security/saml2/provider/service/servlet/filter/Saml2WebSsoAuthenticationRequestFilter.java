/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.saml2.provider.service.servlet.filter;

import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestContextResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;

/**
 * This {@code Filter} formulates a
 * <a href="https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf">SAML 2.0
 * AuthnRequest</a> (line 1968) and redirects to a configured asserting party.
 *
 * <p>
 * It supports the <a href=
 * "https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf">HTTP-Redirect</a>
 * (line 520) and <a href=
 * "https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf">HTTP-POST</a>
 * (line 753) bindings.
 *
 * <p>
 * By default, this {@code Filter} responds to authentication requests at the {@code URI}
 * {@code /saml2/authenticate/{registrationId}}. The {@code URI} template variable
 * {@code {registrationId}} represents the
 * {@link RelyingPartyRegistration#getRegistrationId() registration identifier} of the
 * relying party that is used for initiating the authentication request.
 *
 * @author Filip Hanik
 * @author Josh Cummings
 * @since 5.2
 * @deprecated Use
 * {@link org.springframework.security.saml2.provider.service.web.Saml2WebSsoAuthenticationRequestFilter}
 * instead
 */
@Deprecated
public class Saml2WebSsoAuthenticationRequestFilter
		extends org.springframework.security.saml2.provider.service.web.Saml2WebSsoAuthenticationRequestFilter {

	public Saml2WebSsoAuthenticationRequestFilter(
			RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
		super(relyingPartyRegistrationRepository);
	}

	public Saml2WebSsoAuthenticationRequestFilter(
			Saml2AuthenticationRequestContextResolver authenticationRequestContextResolver,
			Saml2AuthenticationRequestFactory authenticationRequestFactory) {
		super(authenticationRequestContextResolver, authenticationRequestFactory);
	}

	public Saml2WebSsoAuthenticationRequestFilter(Saml2AuthenticationRequestResolver authenticationRequestResolver) {
		super(authenticationRequestResolver);
	}

}
