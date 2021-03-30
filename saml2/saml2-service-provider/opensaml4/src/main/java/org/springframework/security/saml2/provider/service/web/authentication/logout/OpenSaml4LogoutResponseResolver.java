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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import java.time.Clock;
import java.time.Instant;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSamlLogoutResponseResolver.OpenSamlLogoutResponseBuilder;
import org.springframework.util.Assert;

/**
 * A {@link Saml2LogoutResponseResolver} for resolving SAML 2.0 Logout Responses with
 * OpenSAML 4
 *
 * @author Josh Cummings
 * @since 5.5
 */
public class OpenSaml4LogoutResponseResolver implements Saml2LogoutResponseResolver {

	private final OpenSamlLogoutResponseResolver logoutResponseResolver;

	private Clock clock = Clock.systemUTC();

	/**
	 * Construct a {@link OpenSaml4LogoutResponseResolver} with the provided parameters
	 * @param relyingPartyRegistrationResolver the strategy for resolving a
	 * {@link RelyingPartyRegistration}
	 */
	public OpenSaml4LogoutResponseResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		this.logoutResponseResolver = new OpenSamlLogoutResponseResolver(relyingPartyRegistrationResolver);
	}

	/**
	 * Prepare to create, sign, and serialize a SAML 2.0 Logout Response.
	 *
	 * By default, includes a {@code RelayState} based on the {@link HttpServletRequest}
	 * as well as the {@code Destination} and {@code Issuer} based on the
	 * {@link RelyingPartyRegistration} derived from the {@link Authentication}. The
	 * logout response also includes an issued {@link Instant} and is marked as
	 * {@code SUCCESS}.
	 *
	 * The {@link Authentication} must be of type {@link Saml2Authentication} in order to
	 * look up the {@link RelyingPartyRegistration} that holds the signing key.
	 * @param request the HTTP request
	 * @param authentication the current principal details
	 * @return a builder, useful for overriding any aspects of the SAML 2.0 Logout Request
	 * that the resolver supplied
	 */
	@Override
	public Saml2LogoutResponseBuilder<?> resolveLogoutResponse(HttpServletRequest request,
			Authentication authentication) {
		OpenSamlLogoutResponseBuilder builder = this.logoutResponseResolver.resolveLogoutResponse(request,
				authentication);
		if (builder == null) {
			return null;
		}
		return builder.logoutResponse((logoutResponse) -> logoutResponse.setIssueInstant(Instant.now(this.clock)));
	}

	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock must not be null");
		this.clock = clock;
	}

}
