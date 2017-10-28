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
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.token.InMemoryAccessTokenRepository;
import org.springframework.security.oauth2.client.token.OAuth2TokenRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.user.OAuth2User;
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
 *  This <code>Filter</code> will then create an {@link OAuth2AuthorizationCodeAuthenticationToken} with
 *  the {@link OAuth2ParameterNames#CODE} received in the previous step and delegate it to
 *  {@link OAuth2LoginAuthenticationProvider#authenticate(Authentication)} (indirectly via {@link AuthenticationManager}).
 * </li>
 * </ul>
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AbstractAuthenticationProcessingFilter
 * @see OAuth2AuthorizationCodeAuthenticationToken
 * @see OAuth2AuthenticationToken
 * @see OAuth2LoginAuthenticationProvider
 * @see OAuth2AuthorizationRequest
 * @see OAuth2AuthorizationResponse
 * @see AuthorizationRequestRepository
 * @see OAuth2AuthorizationRequestRedirectFilter
 * @see ClientRegistrationRepository
 * @see OAuth2TokenRepository
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.2">Section 4.1.2 Authorization Response</a>
 */
public class OAuth2LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
	public static final String DEFAULT_FILTER_PROCESSES_URI = "/login/oauth2/code/*";
	private static final String AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE = "authorization_request_not_found";
	private ClientRegistrationRepository clientRegistrationRepository;
	private OAuth2AuthorizedClientService<OAuth2AuthorizedClient> authorizedClientService;
	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository =
		new HttpSessionOAuth2AuthorizationRequestRepository();
	private OAuth2TokenRepository<OAuth2AccessToken> accessTokenRepository = new InMemoryAccessTokenRepository();

	public OAuth2LoginAuthenticationFilter() {
		this(DEFAULT_FILTER_PROCESSES_URI);
	}

	public OAuth2LoginAuthenticationFilter(String filterProcessesUrl) {
		super(filterProcessesUrl);
	}

	@Override
	public void afterPropertiesSet() {
		super.afterPropertiesSet();
		Assert.notNull(this.clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(this.authorizedClientService, "authorizedClientService cannot be null");
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

		// The clientRegistration.redirectUri may contain Uri template variables, whether it's configured by
		// the user or configured by default. In these cases, the redirectUri will be expanded and ultimately changed
		// (by OAuth2AuthorizationRequestRedirectFilter) before setting it in the authorization request.
		// The resulting redirectUri used for the authorization request and saved within the AuthorizationRequestRepository
		// MUST BE the same one used to complete the authorization code flow.
		// Therefore, we'll create a copy of the clientRegistration and override the redirectUri
		// with the one contained in authorizationRequest.
		clientRegistration = ClientRegistration.from(clientRegistration)
			.redirectUri(authorizationRequest.getRedirectUri())
			.build();

		OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = new OAuth2AuthorizationCodeAuthenticationToken(
				clientRegistration, new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
		authorizationCodeAuthentication.setDetails(this.authenticationDetailsSource.buildDetails(request));

		OAuth2AuthenticationToken<OAuth2User, OAuth2AuthorizedClient> oauth2Authentication =
			(OAuth2AuthenticationToken<OAuth2User, OAuth2AuthorizedClient>) this.getAuthenticationManager().authenticate(authorizationCodeAuthentication);

		this.authorizedClientService.saveAuthorizedClient(
			oauth2Authentication.getAuthorizedClient(), oauth2Authentication);

		this.accessTokenRepository.saveToken(
			oauth2Authentication.getAuthorizedClient().getAccessToken(),
			oauth2Authentication.getAuthorizedClient().getClientRegistration(),
			oauth2Authentication);

		return oauth2Authentication;
	}

	public final void setClientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	public final void setAuthorizedClientService(OAuth2AuthorizedClientService<OAuth2AuthorizedClient> authorizedClientService) {
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.authorizedClientService = authorizedClientService;
	}

	public final void setAuthorizationRequestRepository(AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
		Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
		this.authorizationRequestRepository = authorizationRequestRepository;
	}

	public final void setAccessTokenRepository(OAuth2TokenRepository<OAuth2AccessToken> accessTokenRepository) {
		Assert.notNull(accessTokenRepository, "accessTokenRepository cannot be null");
		this.accessTokenRepository = accessTokenRepository;
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
