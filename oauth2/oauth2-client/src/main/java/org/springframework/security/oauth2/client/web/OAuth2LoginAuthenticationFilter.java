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

package org.springframework.security.oauth2.client.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.convert.converter.Converter;
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
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * An implementation of an {@link AbstractAuthenticationProcessingFilter} for OAuth 2.0
 * Login.
 *
 * <p>
 * This authentication {@code Filter} handles the processing of an OAuth 2.0 Authorization
 * Response for the authorization code grant flow and delegates an
 * {@link OAuth2LoginAuthenticationToken} to the {@link AuthenticationManager} to log in
 * the End-User.
 *
 * <p>
 * The OAuth 2.0 Authorization Response is processed as follows:
 *
 * <ul>
 * <li>Assuming the End-User (Resource Owner) has granted access to the Client, the
 * Authorization Server will append the {@link OAuth2ParameterNames#CODE code} and
 * {@link OAuth2ParameterNames#STATE state} parameters to the
 * {@link OAuth2ParameterNames#REDIRECT_URI redirect_uri} (provided in the Authorization
 * Request) and redirect the End-User's user-agent back to this {@code Filter} (the
 * Client).</li>
 * <li>This {@code Filter} will then create an {@link OAuth2LoginAuthenticationToken} with
 * the {@link OAuth2ParameterNames#CODE code} received and delegate it to the
 * {@link AuthenticationManager} to authenticate.</li>
 * <li>Upon a successful authentication, an {@link OAuth2AuthenticationToken} is created
 * (representing the End-User {@code Principal}) and associated to the
 * {@link OAuth2AuthorizedClient Authorized Client} using the
 * {@link OAuth2AuthorizedClientRepository}.</li>
 * <li>Finally, the {@link OAuth2AuthenticationToken} is returned and ultimately stored in
 * the {@link SecurityContextRepository} to complete the authentication processing.</li>
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
 * @see OAuth2AuthorizedClient
 * @see OAuth2AuthorizedClientRepository
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section
 * 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-4.1.2">Section 4.1.2 Authorization
 * Response</a>
 */
public class OAuth2LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	/**
	 * The default {@code URI} where this {@code Filter} processes authentication
	 * requests.
	 */
	public static final String DEFAULT_FILTER_PROCESSES_URI = "/login/oauth2/code/*";

	private static final String AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE = "authorization_request_not_found";

	private static final String CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE = "client_registration_not_found";

	private ClientRegistrationRepository clientRegistrationRepository;

	private OAuth2AuthorizedClientRepository authorizedClientRepository;

	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();

	private Converter<OAuth2LoginAuthenticationToken, OAuth2AuthenticationToken> authenticationResultConverter = this::createAuthenticationResult;

	/**
	 * Constructs an {@code OAuth2LoginAuthenticationFilter} using the provided
	 * parameters.
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientService the authorized client service
	 */
	public OAuth2LoginAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientService authorizedClientService) {
		this(clientRegistrationRepository, authorizedClientService, DEFAULT_FILTER_PROCESSES_URI);
	}

	/**
	 * Constructs an {@code OAuth2LoginAuthenticationFilter} using the provided
	 * parameters.
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientService the authorized client service
	 * @param filterProcessesUrl the {@code URI} where this {@code Filter} will process
	 * the authentication requests
	 */
	public OAuth2LoginAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientService authorizedClientService, String filterProcessesUrl) {
		this(clientRegistrationRepository,
				new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService),
				filterProcessesUrl);
	}

	/**
	 * Constructs an {@code OAuth2LoginAuthenticationFilter} using the provided
	 * parameters.
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientRepository the authorized client repository
	 * @param filterProcessesUrl the {@code URI} where this {@code Filter} will process
	 * the authentication requests
	 * @since 5.1
	 */
	public OAuth2LoginAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository, String filterProcessesUrl) {
		super(filterProcessesUrl);
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientRepository = authorizedClientRepository;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		MultiValueMap<String, String> params = OAuth2AuthorizationResponseUtils.toMultiMap(request.getParameterMap());
		if (!OAuth2AuthorizationResponseUtils.isAuthorizationResponse(params)) {
			OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
		OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository
				.removeAuthorizationRequest(request, response);
		if (authorizationRequest == null) {
			OAuth2Error oauth2Error = new OAuth2Error(AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
		String registrationId = authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID);
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
		if (clientRegistration == null) {
			OAuth2Error oauth2Error = new OAuth2Error(CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE,
					"Client Registration not found with Id: " + registrationId, null);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
		// @formatter:off
		String redirectUri = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
				.replaceQuery(null)
				.build()
				.toUriString();
		// @formatter:on
		OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponseUtils.convert(params,
				redirectUri);
		Object authenticationDetails = this.authenticationDetailsSource.buildDetails(request);
		OAuth2LoginAuthenticationToken authenticationRequest = new OAuth2LoginAuthenticationToken(clientRegistration,
				new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
		authenticationRequest.setDetails(authenticationDetails);
		OAuth2LoginAuthenticationToken authenticationResult = (OAuth2LoginAuthenticationToken) this
				.getAuthenticationManager().authenticate(authenticationRequest);
		OAuth2AuthenticationToken oauth2Authentication = this.authenticationResultConverter
				.convert(authenticationResult);
		Assert.notNull(oauth2Authentication, "authentication result cannot be null");
		oauth2Authentication.setDetails(authenticationDetails);
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				authenticationResult.getClientRegistration(), oauth2Authentication.getName(),
				authenticationResult.getAccessToken(), authenticationResult.getRefreshToken());

		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, oauth2Authentication, request, response);
		return oauth2Authentication;
	}

	/**
	 * Sets the repository for stored {@link OAuth2AuthorizationRequest}'s.
	 * @param authorizationRequestRepository the repository for stored
	 * {@link OAuth2AuthorizationRequest}'s
	 */
	public final void setAuthorizationRequestRepository(
			AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
		Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
		this.authorizationRequestRepository = authorizationRequestRepository;
	}

	/**
	 * Sets the converter responsible for converting from
	 * {@link OAuth2LoginAuthenticationToken} to {@link OAuth2AuthenticationToken}
	 * authentication result.
	 * @param authenticationResultConverter the converter for
	 * {@link OAuth2AuthenticationToken}'s
	 * @since 5.6
	 */
	public final void setAuthenticationResultConverter(
			Converter<OAuth2LoginAuthenticationToken, OAuth2AuthenticationToken> authenticationResultConverter) {
		Assert.notNull(authenticationResultConverter, "authenticationResultConverter cannot be null");
		this.authenticationResultConverter = authenticationResultConverter;
	}

	private OAuth2AuthenticationToken createAuthenticationResult(OAuth2LoginAuthenticationToken authenticationResult) {
		return new OAuth2AuthenticationToken(authenticationResult.getPrincipal(), authenticationResult.getAuthorities(),
				authenticationResult.getClientRegistration().getRegistrationId());
	}

}
