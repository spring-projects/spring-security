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

package org.springframework.security.oauth2.client.web.reactive.function.client;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import static org.springframework.security.oauth2.core.web.reactive.function.OAuth2BodyExtractors.oauth2AccessTokenResponse;
import static org.springframework.security.web.http.SecurityHeaders.bearerToken;

/**
 * Provides an easy mechanism for using an {@link OAuth2AuthorizedClient} to make OAuth2 requests by including the
 * token as a Bearer Token.
 *
 * @author Rob Winch
 * @since 5.1
 */
public final class OAuth2AuthorizedClientExchangeFilterFunction implements ExchangeFilterFunction {
	/**
	 * The request attribute name used to locate the {@link OAuth2AuthorizedClient}.
	 */
	private static final String OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME = OAuth2AuthorizedClient.class.getName();

	private Clock clock = Clock.systemUTC();

	private Duration accessTokenExpiresSkew = Duration.ofMinutes(1);

	private ReactiveOAuth2AuthorizedClientService authorizedClientService;

	public OAuth2AuthorizedClientExchangeFilterFunction() {}

	public OAuth2AuthorizedClientExchangeFilterFunction(ReactiveOAuth2AuthorizedClientService authorizedClientService) {
		this.authorizedClientService = authorizedClientService;
	}

	/**
	 * Modifies the {@link ClientRequest#attributes()} to include the {@link OAuth2AuthorizedClient} to be used for
	 * providing the Bearer Token. Example usage:
	 *
	 * <pre>
	 * WebClient webClient = WebClient.builder()
	 *    .filter(new OAuth2AuthorizedClientExchangeFilterFunction(authorizedClientService))
	 *    .build();
	 * Mono<String> response = webClient
	 *    .get()
	 *    .uri(uri)
	 *    .attributes(oauth2AuthorizedClient(authorizedClient))
	 *    // ...
	 *    .retrieve()
	 *    .bodyToMono(String.class);
	 * </pre>
	 *
	 * An attempt to automatically refresh the token will be made if all of the following
	 * are true:
	 *
	 * <ul>
	 * <li>The ReactiveOAuth2AuthorizedClientService on the
	 * {@link OAuth2AuthorizedClientExchangeFilterFunction} is not null</li>
	 * <li>A refresh token is present on the OAuth2AuthorizedClient</li>
	 * <li>The access token will be expired in
	 * {@link #setAccessTokenExpiresSkew(Duration)}</li>
	 * <li>The {@link ReactiveSecurityContextHolder} will be used to attempt to save
	 * the token. If it is empty, then the principal name on the OAuth2AuthorizedClient
	 * will be used to create an Authentication for saving.</li>
	 * </ul>
	 *
	 * @param authorizedClient the {@link OAuth2AuthorizedClient} to use.
	 * @return the {@link Consumer} to populate the
	 */
	public static Consumer<Map<String, Object>> oauth2AuthorizedClient(OAuth2AuthorizedClient authorizedClient) {
		return attributes -> attributes.put(OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME, authorizedClient);
	}

	/**
	 * An access token will be considered expired by comparing its expiration to now +
	 * this skewed Duration. The default is 1 minute.
	 * @param accessTokenExpiresSkew the Duration to use.
	 */
	public void setAccessTokenExpiresSkew(Duration accessTokenExpiresSkew) {
		Assert.notNull(accessTokenExpiresSkew, "accessTokenExpiresSkew cannot be null");
		this.accessTokenExpiresSkew = accessTokenExpiresSkew;
	}

	@Override
	public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
		Optional<OAuth2AuthorizedClient> attribute = request.attribute(OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME)
				.map(OAuth2AuthorizedClient.class::cast);
		return Mono.justOrEmpty(attribute)
				.flatMap(authorizedClient -> authorizedClient(next, authorizedClient))
				.map(authorizedClient -> bearer(request, authorizedClient))
				.flatMap(next::exchange)
				.switchIfEmpty(next.exchange(request));
	}

	private Mono<OAuth2AuthorizedClient> authorizedClient(ExchangeFunction next, OAuth2AuthorizedClient authorizedClient) {
		if (shouldRefresh(authorizedClient)) {
			return refreshAuthorizedClient(next, authorizedClient);
		}
		return Mono.just(authorizedClient);
	}

	private Mono<OAuth2AuthorizedClient> refreshAuthorizedClient(ExchangeFunction next,
			OAuth2AuthorizedClient authorizedClient) {
		ClientRegistration clientRegistration = authorizedClient
				.getClientRegistration();
		String tokenUri = clientRegistration
				.getProviderDetails().getTokenUri();
		ClientRequest request = ClientRequest.create(HttpMethod.POST, URI.create(tokenUri))
				.header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
				.headers(httpBasic(clientRegistration.getClientId(), clientRegistration.getClientSecret()))
				.body(refreshTokenBody(authorizedClient.getRefreshToken().getTokenValue()))
				.build();
		return next.exchange(request)
				.flatMap(response -> response.body(oauth2AccessTokenResponse()))
				.map(accessTokenResponse -> new OAuth2AuthorizedClient(authorizedClient.getClientRegistration(), authorizedClient.getPrincipalName(), accessTokenResponse.getAccessToken(), accessTokenResponse.getRefreshToken()))
				.flatMap(result -> ReactiveSecurityContextHolder.getContext()
						.map(SecurityContext::getAuthentication)
						.defaultIfEmpty(new PrincipalNameAuthentication(authorizedClient.getPrincipalName()))
						.flatMap(principal -> this.authorizedClientService.saveAuthorizedClient(result, principal))
						.thenReturn(result));
	}

	private static Consumer<HttpHeaders> httpBasic(String username, String password) {
		return httpHeaders -> {
			String credentialsString = username + ":" + password;
			byte[] credentialBytes = credentialsString.getBytes(StandardCharsets.ISO_8859_1);
			byte[] encodedBytes = Base64.getEncoder().encode(credentialBytes);
			String encodedCredentials = new String(encodedBytes, StandardCharsets.ISO_8859_1);
			httpHeaders.set(HttpHeaders.AUTHORIZATION, "Basic " + encodedCredentials);
		};
	}

	private boolean shouldRefresh(OAuth2AuthorizedClient authorizedClient) {
		if (this.authorizedClientService == null) {
			return false;
		}
		OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
		if (refreshToken == null) {
			return false;
		}
		Instant now = this.clock.instant();
		Instant expiresAt = authorizedClient.getAccessToken().getExpiresAt();
		if (now.isAfter(expiresAt.minus(this.accessTokenExpiresSkew))) {
			return true;
		}
		return false;
	}

	private ClientRequest bearer(ClientRequest request, OAuth2AuthorizedClient authorizedClient) {
		return ClientRequest.from(request)
					.headers(bearerToken(authorizedClient.getAccessToken().getTokenValue()))
					.build();
	}

	private static BodyInserters.FormInserter<String> refreshTokenBody(String refreshToken) {
		return BodyInserters
				.fromFormData("grant_type", AuthorizationGrantType.REFRESH_TOKEN.getValue())
				.with("refresh_token", refreshToken);
	}

	private static class PrincipalNameAuthentication implements Authentication {
		private final String username;

		private PrincipalNameAuthentication(String username) {
			this.username = username;
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			throw unsupported();
		}

		@Override
		public Object getCredentials() {
			throw unsupported();
		}

		@Override
		public Object getDetails() {
			throw unsupported();
		}

		@Override
		public Object getPrincipal() {
			throw unsupported();
		}

		@Override
		public boolean isAuthenticated() {
			throw unsupported();
		}

		@Override
		public void setAuthenticated(boolean isAuthenticated)
				throws IllegalArgumentException {
			throw unsupported();
		}

		@Override
		public String getName() {
			return this.username;
		}

		private UnsupportedOperationException unsupported() {
			return new UnsupportedOperationException("Not Supported");
		}
	}
}
