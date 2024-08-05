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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import java.time.Clock;
import java.time.Instant;
import java.util.function.Consumer;

import jakarta.servlet.http.HttpServletRequest;
import org.opensaml.saml.saml2.core.LogoutRequest;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.util.Assert;

/**
 * A {@link Saml2LogoutRequestResolver} for resolving SAML 2.0 Logout Requests with
 * OpenSAML 4
 *
 * @author Josh Cummings
 * @author Gerhard Haege
 * @since 5.6
 */
public final class OpenSaml5LogoutRequestResolver implements Saml2LogoutRequestResolver {

	private final BaseOpenSamlLogoutRequestResolver delegate;

	public OpenSaml5LogoutRequestResolver(RelyingPartyRegistrationRepository registrations) {
		this((request, id) -> {
			if (id == null) {
				return null;
			}
			return registrations.findByRegistrationId(id);
		});
	}

	/**
	 * Construct a {@link OpenSaml5LogoutRequestResolver}
	 */
	public OpenSaml5LogoutRequestResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		this.delegate = new BaseOpenSamlLogoutRequestResolver(relyingPartyRegistrationResolver,
				new OpenSaml5Template());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2LogoutRequest resolve(HttpServletRequest request, Authentication authentication) {
		return this.delegate.resolve(request, authentication);
	}

	/**
	 * Set a {@link Consumer} for modifying the OpenSAML {@link LogoutRequest}
	 * @param parametersConsumer a consumer that accepts an
	 * {@link LogoutRequestParameters}
	 */
	public void setParametersConsumer(Consumer<LogoutRequestParameters> parametersConsumer) {
		Assert.notNull(parametersConsumer, "parametersConsumer cannot be null");
		this.delegate
			.setParametersConsumer((parameters) -> parametersConsumer.accept(new LogoutRequestParameters(parameters)));
	}

	/**
	 * Use this {@link Clock} for determining the issued {@link Instant}
	 * @param clock the {@link Clock} to use
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock must not be null");
		this.delegate.setClock(clock);
	}

	/**
	 * Use this {@link Converter} to compute the RelayState
	 * @param relayStateResolver the {@link Converter} to use
	 * @since 6.1
	 */
	public void setRelayStateResolver(Converter<HttpServletRequest, String> relayStateResolver) {
		Assert.notNull(relayStateResolver, "relayStateResolver cannot be null");
		this.delegate.setRelayStateResolver(relayStateResolver);
	}

	public static final class LogoutRequestParameters {

		private final HttpServletRequest request;

		private final RelyingPartyRegistration registration;

		private final Authentication authentication;

		private final LogoutRequest logoutRequest;

		public LogoutRequestParameters(HttpServletRequest request, RelyingPartyRegistration registration,
				Authentication authentication, LogoutRequest logoutRequest) {
			this.request = request;
			this.registration = registration;
			this.authentication = authentication;
			this.logoutRequest = logoutRequest;
		}

		LogoutRequestParameters(BaseOpenSamlLogoutRequestResolver.LogoutRequestParameters parameters) {
			this(parameters.getRequest(), parameters.getRelyingPartyRegistration(), parameters.getAuthentication(),
					parameters.getLogoutRequest());
		}

		public HttpServletRequest getRequest() {
			return this.request;
		}

		public RelyingPartyRegistration getRelyingPartyRegistration() {
			return this.registration;
		}

		public Authentication getAuthentication() {
			return this.authentication;
		}

		public LogoutRequest getLogoutRequest() {
			return this.logoutRequest;
		}

	}

}
