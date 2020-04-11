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

package org.springframework.security.saml2.provider.service.web;

import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

import javax.servlet.http.HttpServletRequest;

/**
 * This {@code Saml2AuthenticationRequestContextResolver} formulates a
 * <a href="https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf">SAML 2.0 AuthnRequest</a> (line 1968)
 *
 * @author Shazin Sadakath
 * @since 5.4
 */
public interface Saml2AuthenticationRequestContextResolver {

	/**
	 * This {@code resolve} method is defined to create a {@link Saml2AuthenticationRequestContext}
	 *
	 *
	 * @param request the current request
	 * @param relyingParty the relying party responsible for saml2 sso authentication
	 * @return the created {@link Saml2AuthenticationRequestContext} for request/relying party combination
	 */
	Saml2AuthenticationRequestContext resolve(HttpServletRequest request,
			RelyingPartyRegistration relyingParty);
}
