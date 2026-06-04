/*
 * Copyright 2004-present the original author or authors.
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
import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.FormPostRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

/**
 * A success handler for issuing a SAML 2.0 Logout Request to the SAML 2.0 Asserting Party
 *
 * @author Josh Cummings
 * @since 5.6
 */
public final class Saml2RelyingPartyInitiatedLogoutSuccessHandler implements LogoutSuccessHandler {

	private final Log logger = LogFactory.getLog(getClass());

	private final Saml2LogoutRequestResolver logoutRequestResolver;

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private final RedirectStrategy formPostRedirectStrategy = new FormPostRedirectStrategy();

	private Saml2LogoutRequestRepository logoutRequestRepository = new HttpSessionLogoutRequestRepository();

	/**
	 * Constructs a {@link Saml2RelyingPartyInitiatedLogoutSuccessHandler} using the
	 * provided parameters
	 * @param logoutRequestResolver the {@link Saml2LogoutRequestResolver} to use
	 */
	public Saml2RelyingPartyInitiatedLogoutSuccessHandler(Saml2LogoutRequestResolver logoutRequestResolver) {
		this.logoutRequestResolver = logoutRequestResolver;
	}

	/**
	 * Produce and send a SAML 2.0 Logout Response based on the SAML 2.0 Logout Request
	 * received from the asserting party
	 * @param request the HTTP request
	 * @param response the HTTP response
	 * @param authentication the current principal details
	 * @throws IOException when failing to write to the response
	 */
	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
			@Nullable Authentication authentication) throws IOException {
		if (authentication == null) {
			this.logger.trace("Returning 401 since no logout request generated");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}
		Saml2LogoutRequest logoutRequest = this.logoutRequestResolver.resolve(request, authentication);
		if (logoutRequest == null) {
			this.logger.trace("Returning 401 since no logout request generated");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}
		this.logoutRequestRepository.saveLogoutRequest(logoutRequest, request, response);
		if (logoutRequest.getBinding() == Saml2MessageBinding.REDIRECT) {
			doRedirect(request, response, logoutRequest);
		}
		else {
			doPost(request, response, logoutRequest);
		}
	}

	/**
	 * Use this {@link Saml2LogoutRequestRepository} for saving the SAML 2.0 Logout
	 * Request
	 * @param logoutRequestRepository the {@link Saml2LogoutRequestRepository} to use
	 */
	public void setLogoutRequestRepository(Saml2LogoutRequestRepository logoutRequestRepository) {
		Assert.notNull(logoutRequestRepository, "logoutRequestRepository cannot be null");
		this.logoutRequestRepository = logoutRequestRepository;
	}

	private void doRedirect(HttpServletRequest request, HttpServletResponse response, Saml2LogoutRequest logoutRequest)
			throws IOException {
		String location = logoutRequest.getLocation();
		String query = logoutRequest.getParametersQuery();
		Assert.notNull(query, "logout request must have a parameters query when using redirect binding");
		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(location).query(query);
		this.redirectStrategy.sendRedirect(request, response, uriBuilder.build(true).toUriString());
	}

	private void doPost(HttpServletRequest request, HttpServletResponse response, Saml2LogoutRequest logoutRequest)
			throws IOException {
		String location = logoutRequest.getLocation();
		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(location);
		addParameter(Saml2ParameterNames.SAML_REQUEST, logoutRequest.getSamlRequest(), uriBuilder);
		addParameter(Saml2ParameterNames.RELAY_STATE, logoutRequest.getRelayState(), uriBuilder);
		this.formPostRedirectStrategy.sendRedirect(request, response, uriBuilder.build(true).toUriString());
	}

	private void addParameter(String name, @Nullable String value, UriComponentsBuilder builder) {
		Assert.hasText(name, "name cannot be empty or null");
		if (StringUtils.hasText(value)) {
			builder.queryParam(UriUtils.encode(name, StandardCharsets.ISO_8859_1),
					UriUtils.encode(value, StandardCharsets.ISO_8859_1));
		}
	}

}
