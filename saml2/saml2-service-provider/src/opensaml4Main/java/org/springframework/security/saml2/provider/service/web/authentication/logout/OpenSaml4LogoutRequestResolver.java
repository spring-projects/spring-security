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
import java.util.function.Consumer;

import jakarta.servlet.http.HttpServletRequest;
import org.opensaml.saml.saml2.core.LogoutRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.util.Assert;

/**
 * A {@link Saml2LogoutRequestResolver} for resolving SAML 2.0 Logout Requests with
 * OpenSAML 4
 *
 * @author Josh Cummings
 * @since 5.6
 */
public final class OpenSaml4LogoutRequestResolver implements Saml2LogoutRequestResolver {

	private final OpenSamlLogoutRequestResolver logoutRequestResolver;

	private Consumer<LogoutRequestParameters> parametersConsumer = (parameters) -> {
	};

	private Clock clock = Clock.systemUTC();

	/**
	 * Construct a {@link OpenSaml4LogoutRequestResolver}
	 */
	public OpenSaml4LogoutRequestResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		this.logoutRequestResolver = new OpenSamlLogoutRequestResolver(relyingPartyRegistrationResolver);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2LogoutRequest resolve(HttpServletRequest request, Authentication authentication) {
		return this.logoutRequestResolver.resolve(request, authentication, (registration, logoutRequest) -> {
			logoutRequest.setIssueInstant(Instant.now(this.clock));
			this.parametersConsumer
					.accept(new LogoutRequestParameters(request, registration, authentication, logoutRequest));
		});
	}

	/**
	 * Set a {@link Consumer} for modifying the OpenSAML {@link LogoutRequest}
	 * @param parametersConsumer a consumer that accepts an
	 * {@link LogoutRequestParameters}
	 */
	public void setParametersConsumer(Consumer<LogoutRequestParameters> parametersConsumer) {
		Assert.notNull(parametersConsumer, "parametersConsumer cannot be null");
		this.parametersConsumer = parametersConsumer;
	}

	/**
	 * Use this {@link Clock} for determining the issued {@link Instant}
	 * @param clock the {@link Clock} to use
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock must not be null");
		this.clock = clock;
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
