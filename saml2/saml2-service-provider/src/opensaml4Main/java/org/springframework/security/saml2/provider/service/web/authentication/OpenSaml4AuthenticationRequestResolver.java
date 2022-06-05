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

package org.springframework.security.saml2.provider.service.web.authentication;

import java.time.Clock;
import java.time.Instant;
import java.util.function.Consumer;

import jakarta.servlet.http.HttpServletRequest;
import org.opensaml.saml.saml2.core.AuthnRequest;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * A strategy for resolving a SAML 2.0 Authentication Request from the
 * {@link HttpServletRequest} using OpenSAML.
 *
 * @author Josh Cummings
 * @since 5.7
 */
public final class OpenSaml4AuthenticationRequestResolver implements Saml2AuthenticationRequestResolver {

	private final OpenSamlAuthenticationRequestResolver authnRequestResolver;

	private Consumer<AuthnRequestContext> contextConsumer = (parameters) -> {
	};

	private Clock clock = Clock.systemUTC();

	/**
	 * Construct a {@link OpenSaml4AuthenticationRequestResolver}
	 */
	public OpenSaml4AuthenticationRequestResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		this.authnRequestResolver = new OpenSamlAuthenticationRequestResolver(relyingPartyRegistrationResolver);
	}

	@Override
	public <T extends AbstractSaml2AuthenticationRequest> T resolve(HttpServletRequest request) {
		return this.authnRequestResolver.resolve(request, (registration, authnRequest) -> {
			authnRequest.setIssueInstant(Instant.now(this.clock));
			this.contextConsumer.accept(new AuthnRequestContext(request, registration, authnRequest));
		});
	}

	/**
	 * Set a {@link Consumer} for modifying the OpenSAML {@link AuthnRequest}
	 * @param contextConsumer a consumer that accepts an {@link AuthnRequestContext}
	 */
	public void setAuthnRequestCustomizer(Consumer<AuthnRequestContext> contextConsumer) {
		Assert.notNull(contextConsumer, "contextConsumer cannot be null");
		this.contextConsumer = contextConsumer;
	}

	/**
	 * Set the {@link RequestMatcher} to use for setting the
	 * {@link OpenSamlAuthenticationRequestResolver#setRequestMatcher(RequestMatcher)}
	 * (RequestMatcher)}
	 * @param requestMatcher the {@link RequestMatcher} to identify authentication
	 * requests.
	 * @since 5.8
	 */
	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.authnRequestResolver.setRequestMatcher(requestMatcher);
	}

	/**
	 * Use this {@link Clock} for generating the issued {@link Instant}
	 * @param clock the {@link Clock} to use
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock must not be null");
		this.clock = clock;
	}

	/**
	 * Use this {@link Converter} to compute the RelayState
	 * @param relayStateResolver the {@link Converter} to use
	 * @since 5.8
	 */
	public void setRelayStateResolver(Converter<HttpServletRequest, String> relayStateResolver) {
		Assert.notNull(relayStateResolver, "relayStateResolver cannot be null");
		this.authnRequestResolver.setRelayStateResolver(relayStateResolver);
	}

	public static final class AuthnRequestContext {

		private final HttpServletRequest request;

		private final RelyingPartyRegistration registration;

		private final AuthnRequest authnRequest;

		public AuthnRequestContext(HttpServletRequest request, RelyingPartyRegistration registration,
				AuthnRequest authnRequest) {
			this.request = request;
			this.registration = registration;
			this.authnRequest = authnRequest;
		}

		public HttpServletRequest getRequest() {
			return this.request;
		}

		public RelyingPartyRegistration getRelyingPartyRegistration() {
			return this.registration;
		}

		public AuthnRequest getAuthnRequest() {
			return this.authnRequest;
		}

	}

}
