/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.web;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * An implementation of an {@link AbstractAuthenticationProcessingFilter} that handles
 * the processing of an <i>OAuth 2.0 Authorization Response</i> for the authorization code grant flow.
 *
 * <p>
 * This <code>Filter</code> processes the <i>Authorization Response</i> as follows:
 *
 * <ul>
 * <li>
 *	Assuming the resource owner (end-user) has granted access to the client, the authorization server will append the
 *	{@link OAuth2ParameterNames#CODE} and {@link OAuth2ParameterNames#STATE} (if provided in the <i>Authorization Request</i>) parameters
 *	to the {@link OAuth2ParameterNames#REDIRECT_URI} (provided in the <i>Authorization Request</i>)
 *	and redirect the end-user's user-agent back to this <code>Filter</code> (the client).
 * </li>
 * <li>
 *  This <code>Filter</code> will then create an {@link OAuth2LoginAuthenticationToken} with
 *  the {@link OAuth2ParameterNames#CODE} received in the previous step and delegate it to
 *  {@link OAuth2LoginAuthenticationProvider#authenticate(Authentication)} (indirectly via {@link AuthenticationManager}).
 * </li>
 * </ul>
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AbstractAuthenticationProcessingFilter
 * @see OAuth2LoginAuthenticationToken
 * @see OAuth2AuthenticationToken
 * @see OAuth2LoginAuthenticationProvider
 * @see OAuth2AuthorizationRequest
 * @see OAuth2AuthorizationResponse
 * @see AuthorizationRequestRepository
 * @see OAuth2AuthorizationRequestRedirectFilter
 * @see ClientRegistrationRepository
 * @see OAuth2AuthorizedClientService
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.2">Section 4.1.2 Authorization Response</a>
 */
public class OAuth2LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
	public static final String DEFAULT_FILTER_PROCESSES_URI = "/login/oauth2/code/*";
	private static final String AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE = "authorization_request_not_found";
	private ClientRegistrationRepository clientRegistrationRepository;
	private OAuth2AuthorizedClientService authorizedClientService;
	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository =
		new HttpSessionOAuth2AuthorizationRequestRepository();

	public OAuth2LoginAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository,
											OAuth2AuthorizedClientService authorizedClientService) {
		this(DEFAULT_FILTER_PROCESSES_URI, clientRegistrationRepository, authorizedClientService);
	}

	public OAuth2LoginAuthenticationFilter(String filterProcessesUrl,
											ClientRegistrationRepository clientRegistrationRepository,
											OAuth2AuthorizedClientService authorizedClientService) {
		super(filterProcessesUrl);
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientService = authorizedClientService;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		if (!this.authorizationResponseSuccess(request) && !this.authorizationResponseError(request)) {
			OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
		OAuth2AuthorizationResponse authorizationResponse = this.convert(request);

		OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository.loadAuthorizationRequest(request);
		if (authorizationRequest == null) {
			OAuth2Error oauth2Error = new OAuth2Error(AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
		this.authorizationRequestRepository.removeAuthorizationRequest(request);

		String registrationId = (String)authorizationRequest.getAdditionalParameters().get(OAuth2ParameterNames.REGISTRATION_ID);
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);

		OAuth2LoginAuthenticationToken authenticationRequest = new OAuth2LoginAuthenticationToken(
				clientRegistration, new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
		authenticationRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));

		OAuth2LoginAuthenticationToken authenticationResult =
			(OAuth2LoginAuthenticationToken)this.getAuthenticationManager().authenticate(authenticationRequest);

		OAuth2AuthenticationToken oauth2Authentication = new OAuth2AuthenticationToken(
			authenticationResult.getPrincipal(),
			authenticationResult.getAuthorities(),
			authenticationResult.getClientRegistration().getRegistrationId());

		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
			authenticationResult.getClientRegistration(),
			oauth2Authentication.getName(),
			authenticationResult.getAccessToken());

		this.authorizedClientService.saveAuthorizedClient(authorizedClient, oauth2Authentication);

		return oauth2Authentication;
	}

	public final void setAuthorizationRequestRepository(AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
		Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
		this.authorizationRequestRepository = authorizationRequestRepository;
	}

	private OAuth2AuthorizationResponse convert(HttpServletRequest request) {
		String code = request.getParameter(OAuth2ParameterNames.CODE);
		String errorCode = request.getParameter(OAuth2ParameterNames.ERROR);
		String state = request.getParameter(OAuth2ParameterNames.STATE);
		String redirectUri = request.getRequestURL().toString();

		if (StringUtils.hasText(code)) {
			return OAuth2AuthorizationResponse.success(code)
				.redirectUri(redirectUri)
				.state(state)
				.build();
		} else {
			String errorDescription = request.getParameter(OAuth2ParameterNames.ERROR_DESCRIPTION);
			String errorUri = request.getParameter(OAuth2ParameterNames.ERROR_URI);
			return OAuth2AuthorizationResponse.error(errorCode)
				.redirectUri(redirectUri)
				.errorDescription(errorDescription)
				.errorUri(errorUri)
				.state(state)
				.build();
		}
	}

	private boolean authorizationResponseSuccess(HttpServletRequest request) {
		return StringUtils.hasText(request.getParameter(OAuth2ParameterNames.CODE)) &&
			StringUtils.hasText(request.getParameter(OAuth2ParameterNames.STATE));
	}

	private boolean authorizationResponseError(HttpServletRequest request) {
		return StringUtils.hasText(request.getParameter(OAuth2ParameterNames.ERROR)) &&
			StringUtils.hasText(request.getParameter(OAuth2ParameterNames.STATE));
	}
}
