/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.oauth2.client.web.server;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

/**
 * Converts from a {@link ServerWebExchange} to an {@link OAuth2AuthorizationCodeAuthenticationToken} that can be authenticated. The
 * converter does not validate any errors it only performs a conversion.
 * @author Rob Winch
 * @since 5.1
 * @see org.springframework.security.web.server.authentication.AuthenticationWebFilter#setServerAuthenticationConverter(ServerAuthenticationConverter)
 */
public class ServerOAuth2AuthorizationCodeAuthenticationTokenConverter
		implements ServerAuthenticationConverter {

	static final String AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE = "authorization_request_not_found";

	static final String CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE = "client_registration_not_found";

	private ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository =
			new WebSessionOAuth2ServerAuthorizationRequestRepository();

	private final ReactiveClientRegistrationRepository clientRegistrationRepository;

	public ServerOAuth2AuthorizationCodeAuthenticationTokenConverter(
			ReactiveClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	/**
	 * Sets the {@link ServerAuthorizationRequestRepository} to be used. The default is
	 * {@link WebSessionOAuth2ServerAuthorizationRequestRepository}.
	 * @param authorizationRequestRepository the repository to use.
	 */
	public void setAuthorizationRequestRepository(
			ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
		Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
		this.authorizationRequestRepository = authorizationRequestRepository;
	}

	@Override
	public Mono<Authentication> convert(ServerWebExchange serverWebExchange) {
		return this.authorizationRequestRepository.removeAuthorizationRequest(serverWebExchange)
			.switchIfEmpty(oauth2AuthorizationException(AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE))
			.flatMap(authorizationRequest -> authenticationRequest(serverWebExchange, authorizationRequest));
	}

	private <T> Mono<T> oauth2AuthorizationException(String errorCode) {
		return Mono.defer(() -> {
			OAuth2Error oauth2Error = new OAuth2Error(errorCode);
			return Mono.error(new OAuth2AuthorizationException(oauth2Error));
		});
	}

	private Mono<OAuth2AuthorizationCodeAuthenticationToken> authenticationRequest(ServerWebExchange exchange, OAuth2AuthorizationRequest authorizationRequest) {
		return Mono.just(authorizationRequest)
				.map(OAuth2AuthorizationRequest::getAdditionalParameters)
				.flatMap(additionalParams -> {
					String id = (String) additionalParams.get(OAuth2ParameterNames.REGISTRATION_ID);
					if (id == null) {
						return oauth2AuthorizationException(CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE);
					}
					return this.clientRegistrationRepository.findByRegistrationId(id);
				})
				.switchIfEmpty(oauth2AuthorizationException(CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE))
				.map(clientRegistration -> {
					OAuth2AuthorizationResponse authorizationResponse = convertResponse(exchange);
					OAuth2AuthorizationCodeAuthenticationToken authenticationRequest = new OAuth2AuthorizationCodeAuthenticationToken(
							clientRegistration, new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
					return authenticationRequest;
				});
	}

	private static OAuth2AuthorizationResponse convertResponse(ServerWebExchange exchange) {
		String redirectUri = UriComponentsBuilder.fromUri(exchange.getRequest().getURI())
				.build()
				.toUriString();
		return OAuth2AuthorizationResponseUtils
				.convert(exchange.getRequest().getQueryParams(), redirectUri);
	}
}
