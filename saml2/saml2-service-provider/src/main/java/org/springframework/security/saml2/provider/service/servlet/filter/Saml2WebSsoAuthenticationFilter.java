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

package org.springframework.security.saml2.provider.service.servlet.filter;

import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;

/**
 * @since 5.2
 * @deprecated Use
 * {@link org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter}
 * instead
 */
@Deprecated
public class Saml2WebSsoAuthenticationFilter
		extends org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter {

	public Saml2WebSsoAuthenticationFilter(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
		super(relyingPartyRegistrationRepository);
	}

	public Saml2WebSsoAuthenticationFilter(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
			String filterProcessesUrl) {
		super(relyingPartyRegistrationRepository, filterProcessesUrl);
	}

	public Saml2WebSsoAuthenticationFilter(AuthenticationConverter authenticationConverter, String filterProcessesUrl) {
		super(authenticationConverter, filterProcessesUrl);
	}

}
