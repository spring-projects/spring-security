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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidatorParameters;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
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
 * @see Saml2LogoutRequestRepository
 * @see Saml2LogoutResponseValidator
 */
public final class Saml2LogoutResponseFilter extends OncePerRequestFilter {

	private final Log logger = LogFactory.getLog(getClass());

	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	private final Saml2LogoutResponseValidator logoutResponseValidator;

	private final LogoutSuccessHandler logoutSuccessHandler;

	private Saml2LogoutRequestRepository logoutRequestRepository = new HttpSessionLogoutRequestRepository();

	private RequestMatcher logoutRequestMatcher = new AntPathRequestMatcher("/logout/saml2/slo");

	/**
	 * Constructs a {@link Saml2LogoutResponseFilter} for accepting SAML 2.0 Logout
	 * Responses from the asserting party
	 * @param relyingPartyRegistrationResolver the strategy for resolving a
	 * {@link RelyingPartyRegistration}
	 * @param logoutResponseValidator authenticates the SAML 2.0 Logout Response
	 * @param logoutSuccessHandler the action to perform now that logout has succeeded
	 */
	public Saml2LogoutResponseFilter(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
			Saml2LogoutResponseValidator logoutResponseValidator, LogoutSuccessHandler logoutSuccessHandler) {
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
		this.logoutResponseValidator = logoutResponseValidator;
		this.logoutSuccessHandler = logoutSuccessHandler;
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

		if (request.getParameter(Saml2ParameterNames.SAML_RESPONSE) == null) {
			chain.doFilter(request, response);
			return;
		}

		Saml2LogoutRequest logoutRequest = this.logoutRequestRepository.removeLogoutRequest(request, response);
		if (logoutRequest == null) {
			this.logger.trace("Did not process logout response since could not find associated LogoutRequest");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Failed to find associated LogoutRequest");
			return;
		}
		RelyingPartyRegistration registration = this.relyingPartyRegistrationResolver.resolve(request,
				logoutRequest.getRelyingPartyRegistrationId());
		if (registration == null) {
			this.logger
					.trace("Did not process logout response since failed to find associated RelyingPartyRegistration");
			Saml2Error error = new Saml2Error(Saml2ErrorCodes.RELYING_PARTY_REGISTRATION_NOT_FOUND,
					"Failed to find associated RelyingPartyRegistration");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST, error.toString());
			return;
		}
		if (registration.getSingleLogoutServiceResponseLocation() == null) {
			this.logger.trace(
					"Did not process logout response since RelyingPartyRegistration has not been configured with a logout response endpoint");
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		Saml2MessageBinding saml2MessageBinding = Saml2MessageBindingUtils.resolveBinding(request);
		if (!registration.getSingleLogoutServiceBindings().contains(saml2MessageBinding)) {
			this.logger.trace("Did not process logout response since used incorrect binding");
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		String serialized = request.getParameter(Saml2ParameterNames.SAML_RESPONSE);
		Saml2LogoutResponse logoutResponse = Saml2LogoutResponse.withRelyingPartyRegistration(registration)
				.samlResponse(serialized).relayState(request.getParameter(Saml2ParameterNames.RELAY_STATE))
				.binding(saml2MessageBinding).location(registration.getSingleLogoutServiceResponseLocation())
				.parameters((params) -> params.put(Saml2ParameterNames.SIG_ALG,
						request.getParameter(Saml2ParameterNames.SIG_ALG)))
				.parameters((params) -> params.put(Saml2ParameterNames.SIGNATURE,
						request.getParameter(Saml2ParameterNames.SIGNATURE)))
				.parametersQuery((params) -> request.getQueryString()).build();
		Saml2LogoutResponseValidatorParameters parameters = new Saml2LogoutResponseValidatorParameters(logoutResponse,
				logoutRequest, registration);
		Saml2LogoutValidatorResult result = this.logoutResponseValidator.validate(parameters);
		if (result.hasErrors()) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, result.getErrors().iterator().next().toString());
			this.logger.debug(LogMessage.format("Failed to validate LogoutResponse: %s", result.getErrors()));
			return;
		}
		this.logoutSuccessHandler.onLogoutSuccess(request, response, null);
	}

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

}
