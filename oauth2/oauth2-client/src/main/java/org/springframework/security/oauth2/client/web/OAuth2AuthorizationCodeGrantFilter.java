/*
 * Copyright 2002-2018 the original author or authors.
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

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * A {@code Filter} for the OAuth 2.0 Authorization Code Grant,
 * which handles the processing of the OAuth 2.0 Authorization Response.
 *
 * <p>
 * The OAuth 2.0 Authorization Response is processed as follows:
 *
 * <ul>
 * <li>
 *	Assuming the End-User (Resource Owner) has granted access to the Client, the Authorization Server will append the
 *	{@link OAuth2ParameterNames#CODE code} and {@link OAuth2ParameterNames#STATE state} parameters
 *	to the {@link OAuth2ParameterNames#REDIRECT_URI redirect_uri} (provided in the Authorization Request)
 *	and redirect the End-User's user-agent back to this {@code Filter} (the Client).
 * </li>
 * <li>
 *  This {@code Filter} will then create an {@link OAuth2AuthorizationCodeAuthenticationToken} with
 *  the {@link OAuth2ParameterNames#CODE code} received and
 *  delegate it to the {@link AuthenticationManager} to authenticate.
 * </li>
 * <li>
 *  Upon a successful authentication, an {@link OAuth2AuthorizedClient Authorized Client} is created by associating the
 *  {@link OAuth2AuthorizationCodeAuthenticationToken#getClientRegistration() client} to the
 *  {@link OAuth2AuthorizationCodeAuthenticationToken#getAccessToken() access token} and current {@code Principal}
 *  and saving it via the {@link OAuth2AuthorizedClientService}.
 * </li>
 * </ul>
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2AuthorizationCodeAuthenticationToken
 * @see OAuth2AuthorizationCodeAuthenticationProvider
 * @see OAuth2AuthorizationRequest
 * @see OAuth2AuthorizationResponse
 * @see AuthorizationRequestRepository
 * @see OAuth2AuthorizationRequestRedirectFilter
 * @see ClientRegistrationRepository
 * @see OAuth2AuthorizedClient
 * @see OAuth2AuthorizedClientService
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.2">Section 4.1.2 Authorization Response</a>
 */
public class OAuth2AuthorizationCodeGrantFilter extends OncePerRequestFilter {
	private final ClientRegistrationRepository clientRegistrationRepository;
	private final OAuth2AuthorizedClientService authorizedClientService;
	private final AuthenticationManager authenticationManager;
	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository =
		new HttpSessionOAuth2AuthorizationRequestRepository();
	private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeGrantFilter} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientService the authorized client service
	 * @param authenticationManager the authentication manager
	 */
	public OAuth2AuthorizationCodeGrantFilter(ClientRegistrationRepository clientRegistrationRepository,
												OAuth2AuthorizedClientService authorizedClientService,
												AuthenticationManager authenticationManager) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientService = authorizedClientService;
		this.authenticationManager = authenticationManager;
	}

	/**
	 * Sets the repository for stored {@link OAuth2AuthorizationRequest}'s.
	 *
	 * @param authorizationRequestRepository the repository for stored {@link OAuth2AuthorizationRequest}'s
	 */
	public final void setAuthorizationRequestRepository(AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
		Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
		this.authorizationRequestRepository = authorizationRequestRepository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {

		if (this.shouldProcessAuthorizationResponse(request, response)) {
			this.processAuthorizationResponse(request, response);
			return;
		}

		filterChain.doFilter(request, response);
	}

	private boolean shouldProcessAuthorizationResponse(HttpServletRequest request, HttpServletResponse response) {
		if (OAuth2AuthorizationResponseUtils.authorizationResponse(request) &&
			(this.authorizationRequestRepository.loadAuthorizationRequest(request) != null)) {
			return true;
		}
		return false;
	}

	private void processAuthorizationResponse(HttpServletRequest request, HttpServletResponse response)
		throws ServletException, IOException {

		OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository.loadAuthorizationRequest(request);
		this.authorizationRequestRepository.removeAuthorizationRequest(request);

		String registrationId = (String) authorizationRequest.getAdditionalParameters().get(OAuth2ParameterNames.REGISTRATION_ID);
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);

		OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponseUtils.convert(request);

		OAuth2AuthorizationCodeAuthenticationToken authenticationRequest = new OAuth2AuthorizationCodeAuthenticationToken(
			clientRegistration, new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
		authenticationRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));

		OAuth2AuthorizationCodeAuthenticationToken authenticationResult;

		try {
			authenticationResult = (OAuth2AuthorizationCodeAuthenticationToken)
				this.authenticationManager.authenticate(authenticationRequest);
		} catch (OAuth2AuthenticationException ex) {
			OAuth2Error error = ex.getError();
			UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUriString(authorizationResponse.getRedirectUri())
				.queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());
			if (!StringUtils.isEmpty(error.getDescription())) {
				uriBuilder.queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION, error.getDescription());
			}
			if (!StringUtils.isEmpty(error.getUri())) {
				uriBuilder.queryParam(OAuth2ParameterNames.ERROR_URI, error.getUri());
			}
			this.redirectStrategy.sendRedirect(request, response, uriBuilder.build().encode().toString());
			return;
		}

		Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();

		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
			authenticationResult.getClientRegistration(),
			currentAuthentication.getName(),
			authenticationResult.getAccessToken());

		this.authorizedClientService.saveAuthorizedClient(authorizedClient, currentAuthentication);

		this.redirectStrategy.sendRedirect(request, response, authorizationResponse.getRedirectUri());
	}
}
