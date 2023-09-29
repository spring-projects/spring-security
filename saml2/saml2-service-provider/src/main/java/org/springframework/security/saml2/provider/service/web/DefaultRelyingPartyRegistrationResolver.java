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

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationPlaceholderResolvers.UriResolver;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * A {@link Converter} that resolves a {@link RelyingPartyRegistration} by extracting the
 * registration id from the request, querying a
 * {@link RelyingPartyRegistrationRepository}, and resolving any template values.
 *
 * @author Josh Cummings
 * @since 5.4
 */
public final class DefaultRelyingPartyRegistrationResolver
		implements Converter<HttpServletRequest, RelyingPartyRegistration>, RelyingPartyRegistrationResolver {

	private Log logger = LogFactory.getLog(getClass());

	private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

	private final RequestMatcher registrationRequestMatcher = new AntPathRequestMatcher("/**/{registrationId}");

	public DefaultRelyingPartyRegistrationResolver(
			RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
		Assert.notNull(relyingPartyRegistrationRepository, "relyingPartyRegistrationRepository cannot be null");
		this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RelyingPartyRegistration convert(HttpServletRequest request) {
		return resolve(request, null);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RelyingPartyRegistration resolve(HttpServletRequest request, String relyingPartyRegistrationId) {
		if (relyingPartyRegistrationId == null) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Attempting to resolve from " + this.registrationRequestMatcher
						+ " since registrationId is null");
			}
			relyingPartyRegistrationId = this.registrationRequestMatcher.matcher(request)
				.getVariables()
				.get("registrationId");
		}
		if (relyingPartyRegistrationId == null) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Returning null registration since registrationId is null");
			}
			return null;
		}
		RelyingPartyRegistration registration = this.relyingPartyRegistrationRepository
			.findByRegistrationId(relyingPartyRegistrationId);
		if (registration == null) {
			return null;
		}
		UriResolver uriResolver = RelyingPartyRegistrationPlaceholderResolvers.uriResolver(request, registration);
		return registration.mutate()
			.entityId(uriResolver.resolve(registration.getEntityId()))
			.assertionConsumerServiceLocation(uriResolver.resolve(registration.getAssertionConsumerServiceLocation()))
			.singleLogoutServiceLocation(uriResolver.resolve(registration.getSingleLogoutServiceLocation()))
			.singleLogoutServiceResponseLocation(
					uriResolver.resolve(registration.getSingleLogoutServiceResponseLocation()))
			.build();
	}

}
