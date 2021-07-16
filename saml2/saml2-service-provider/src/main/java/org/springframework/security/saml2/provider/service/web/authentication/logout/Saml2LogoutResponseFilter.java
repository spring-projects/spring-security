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

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutAuthenticatorResult;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseAuthenticator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseAuthenticatorParameters;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A filter for handling a &lt;saml2:LogoutResponse&gt; sent from the asserting party. A
 * &lt;saml2:LogoutResponse&gt; is sent in response to a &lt;saml2:LogoutRequest&gt;
 * already sent by the relying party.
 *
 * Note that before a &lt;saml2:LogoutRequest&gt; is sent, the user is logged out. Given
 * that, this implementation should not use any {@link LogoutSuccessHandler} that relies
 * on the user being logged in.
 *
 * @author Josh Cummings
 * @since 5.6
 */
public final class Saml2LogoutResponseFilter extends OncePerRequestFilter {

	private static final String DEFAULT_LOGOUT_ENDPOINT = "/logout/saml2/slo";

	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	private final Saml2LogoutResponseAuthenticator logoutResponseAuthenticator;

	private Saml2LogoutRequestRepository logoutRequestRepository = new HttpSessionLogoutRequestRepository();

	private RequestMatcher logoutRequestMatcher = new AntPathRequestMatcher(DEFAULT_LOGOUT_ENDPOINT);

	private LogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();

	/**
	 * Constructs a {@link Saml2LogoutResponseFilter} for accepting SAML 2.0 Logout
	 * Responses from the asserting party
	 * @param relyingPartyRegistrationResolver the strategy for resolving a
	 * {@link RelyingPartyRegistration}
	 * @param logoutResponseAuthenticator authenticates the SAML 2.0 Logout Response
	 */
	public Saml2LogoutResponseFilter(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
			Saml2LogoutResponseAuthenticator logoutResponseAuthenticator) {
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
		this.logoutResponseAuthenticator = logoutResponseAuthenticator;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {

		if (!this.logoutRequestMatcher.matches(request)) {
			chain.doFilter(request, response);
			return;
		}

		if (request.getParameter("SAMLResponse") == null) {
			chain.doFilter(request, response);
			return;
		}

		String serialized = request.getParameter("SAMLResponse");
		Saml2LogoutRequest logoutRequest = this.logoutRequestRepository.removeLogoutRequest(request, response);
		if (logoutRequest == null) {
			Saml2Error error = new Saml2Error(Saml2ErrorCodes.INVALID_REQUEST,
					"Failed to find associated LogoutRequest");
			throw new Saml2AuthenticationException(error);
		}
		RelyingPartyRegistration registration = this.relyingPartyRegistrationResolver.resolve(request,
				logoutRequest.getRelyingPartyRegistrationId());
		Saml2LogoutResponse logoutResponse = Saml2LogoutResponse.withRelyingPartyRegistration(registration)
				.samlResponse(serialized).relayState(request.getParameter("RelayState"))
				.parameters((params) -> params.put("SigAlg", request.getParameter("SigAlg")))
				.parameters((params) -> params.put("Signature", request.getParameter("Signature"))).build();
		Saml2LogoutResponseAuthenticatorParameters parameters = new Saml2LogoutResponseAuthenticatorParameters(
				logoutResponse, logoutRequest, registration);
		Saml2LogoutAuthenticatorResult result = this.logoutResponseAuthenticator.authenticate(parameters);
		if (result.hasErrors()) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, result.getErrors().iterator().next().toString());
			return;
		}
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		this.logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
	}

	/**
	 * Use this {@link RequestMatcher} for requests
	 *
	 * This is handy when your asserting party needs it to be a specific endpoint instead
	 * of the default.
	 * @param logoutRequestMatcher the {@link RequestMatcher} to use
	 */
	public void setLogoutRequestMatcher(RequestMatcher logoutRequestMatcher) {
		Assert.notNull(logoutRequestMatcher, "logoutRequestMatcher cannot be null");
		this.logoutRequestMatcher = logoutRequestMatcher;
	}

	/**
	 * Use this {@link Saml2LogoutRequestRepository} for retrieving the SAML 2.0 Logout
	 * Request associated with the request's {@code RelayState}
	 * @param logoutRequestRepository the {@link Saml2LogoutRequestRepository} to use
	 */
	public void setLogoutRequestRepository(Saml2LogoutRequestRepository logoutRequestRepository) {
		Assert.notNull(logoutRequestRepository, "logoutRequestRepository cannot be null");
		this.logoutRequestRepository = logoutRequestRepository;
	}

	/**
	 * Use this {@link LogoutSuccessHandler} when complete
	 *
	 * Note that when a &lt;saml2:LogoutResponse&gt; is received, the end user is already
	 * logged out. Any {@link LogoutSuccessHandler} used here should not rely on the
	 * {@link Authentication}. {@link SimpleUrlLogoutSuccessHandler} is an example of
	 * this.
	 * @param logoutSuccessHandler the {@link LogoutSuccessHandler} to use
	 * @see SimpleUrlLogoutSuccessHandler
	 */
	public void setLogoutSuccessHandler(LogoutSuccessHandler logoutSuccessHandler) {
		Assert.notNull(logoutSuccessHandler, "logoutSuccessHandler cannot be null");
		this.logoutSuccessHandler = logoutSuccessHandler;
	}

}
