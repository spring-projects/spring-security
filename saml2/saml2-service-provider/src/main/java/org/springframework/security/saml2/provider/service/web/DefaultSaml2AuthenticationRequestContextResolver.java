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

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.Assert;

/**
 * The default implementation for {@link Saml2AuthenticationRequestContextResolver}
 * which uses the current request and given relying party to formulate a {@link Saml2AuthenticationRequestContext}
 *
 * @author Shazin Sadakath
 * @author Josh Cummings
 * @since 5.4
 */
public final class DefaultSaml2AuthenticationRequestContextResolver implements Saml2AuthenticationRequestContextResolver {

	private final Log logger = LogFactory.getLog(getClass());

	private final Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver;

	public DefaultSaml2AuthenticationRequestContextResolver
			(Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver) {
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2AuthenticationRequestContext resolve(HttpServletRequest request) {
		Assert.notNull(request, "request cannot be null");
		RelyingPartyRegistration relyingParty = this.relyingPartyRegistrationResolver.convert(request);
		if (relyingParty == null) {
			return null;
		}
		if (this.logger.isDebugEnabled()) {
			this.logger.debug("Creating SAML 2.0 Authentication Request for Asserting Party [" +
					relyingParty.getRegistrationId() + "]");
		}
		return createRedirectAuthenticationRequestContext(request, relyingParty);
	}

	private Saml2AuthenticationRequestContext createRedirectAuthenticationRequestContext(
			HttpServletRequest request, RelyingPartyRegistration relyingParty) {

		return Saml2AuthenticationRequestContext.builder()
				.issuer(relyingParty.getEntityId())
				.relyingPartyRegistration(relyingParty)
				.assertionConsumerServiceUrl(relyingParty.getAssertionConsumerServiceLocation())
				.relayState(request.getParameter("RelayState"))
				.build();
	}
}
