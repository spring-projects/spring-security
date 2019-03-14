/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.authentication;

import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.AUDIENCE;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.CLIENT_ID;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.EXPIRES_AT;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.ISSUED_AT;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.ISSUER;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.NOT_BEFORE;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.SCOPE;

/**
 * An {@link ReactiveAuthenticationManager} implementation for opaque
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>s,
 * using an
 * <a href="https://tools.ietf.org/html/rfc7662" target="_blank">OAuth 2.0 Introspection Endpoint</a>
 * to check the token's validity and reveal its attributes.
 * <p>
 * This {@link ReactiveAuthenticationManager} is responsible for introspecting and verifying an opaque access token,
 * returning its attributes set as part of the {@see Authentication} statement.
 * <p>
 * Scopes are translated into {@link GrantedAuthority}s according to the following algorithm:
 * <ol>
 * <li>
 * If there is a "scope" attribute, then convert to a {@link Collection} of {@link String}s.
 * <li>
 * Take the resulting {@link Collection} and prepend the "SCOPE_" keyword to each element, adding as {@link GrantedAuthority}s.
 * </ol>
 *
 * @author Josh Cummings
 * @since 5.2
 * @see ReactiveAuthenticationManager
 */
public class OAuth2IntrospectionReactiveAuthenticationManager implements ReactiveAuthenticationManager {
	private URI introspectionUri;
	private WebClient webClient;

	/**
	 * Creates a {@code OAuth2IntrospectionReactiveAuthenticationManager} with the provided parameters
	 *
	 * @param introspectionUri The introspection endpoint uri
	 * @param clientId The client id authorized to introspect
	 * @param clientSecret The client secret for the authorized client
	 */
	public OAuth2IntrospectionReactiveAuthenticationManager(String introspectionUri,
			String clientId, String clientSecret) {

		Assert.hasText(introspectionUri, "introspectionUri cannot be empty");
		Assert.hasText(clientId, "clientId cannot be empty");
		Assert.notNull(clientSecret, "clientSecret cannot be null");

		this.introspectionUri = URI.create(introspectionUri);
		this.webClient = WebClient.builder()
				.defaultHeader(HttpHeaders.AUTHORIZATION, basicHeaderValue(clientId, clientSecret))
				.build();
	}

	/**
	 * Creates a {@code OAuth2IntrospectionReactiveAuthenticationManager} with the provided parameters
	 *
	 * @param introspectionUri The introspection endpoint uri
	 * @param webClient The client for performing the introspection request
	 */
	public OAuth2IntrospectionReactiveAuthenticationManager(String introspectionUri,
			WebClient webClient) {

		Assert.hasText(introspectionUri, "introspectionUri cannot be null");
		Assert.notNull(webClient, "webClient cannot be null");

		this.introspectionUri = URI.create(introspectionUri);
		this.webClient = webClient;
	}

	private static String basicHeaderValue(String clientId, String clientSecret) {
		String headerValue = clientId + ":";
		if (StringUtils.hasText(clientSecret)) {
			headerValue += clientSecret;
		}
		return "Basic " + Base64.getEncoder().encodeToString(headerValue.getBytes(StandardCharsets.UTF_8));
	}

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		return Mono.justOrEmpty(authentication)
				.filter(BearerTokenAuthenticationToken.class::isInstance)
				.cast(BearerTokenAuthenticationToken.class)
				.map(BearerTokenAuthenticationToken::getToken)
				.flatMap(this::authenticate)
				.cast(Authentication.class);
	}

	private Mono<OAuth2IntrospectionAuthenticationToken> authenticate(String token) {
		return introspect(token)
				.map(response -> {
					Map<String, Object> claims = convertClaimsSet(response);
					Instant iat = (Instant) claims.get(ISSUED_AT);
					Instant exp = (Instant) claims.get(EXPIRES_AT);

					// construct token
					OAuth2AccessToken accessToken =
							new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token, iat, exp);
					Collection<GrantedAuthority> authorities = extractAuthorities(claims);
					return new OAuth2IntrospectionAuthenticationToken(accessToken, claims, authorities);
				});
	}

	private Mono<TokenIntrospectionSuccessResponse> introspect(String token) {
		return Mono.just(token)
				.flatMap(this::makeRequest)
				.flatMap(this::adaptToNimbusResponse)
				.map(this::parseNimbusResponse)
				.map(this::castToNimbusSuccess)
				.doOnNext(response -> validate(token, response))
				.onErrorMap(e -> !(e instanceof OAuth2AuthenticationException), this::onError);
	}

	private Mono<ClientResponse> makeRequest(String token) {
		return this.webClient.post()
				.uri(this.introspectionUri)
				.header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_UTF8_VALUE)
				.body(BodyInserters.fromFormData("token", token))
				.exchange();
	}

	private Mono<HTTPResponse> adaptToNimbusResponse(ClientResponse responseEntity) {
		HTTPResponse response = new HTTPResponse(responseEntity.rawStatusCode());
		response.setHeader(HttpHeaders.CONTENT_TYPE, responseEntity.headers().contentType().get().toString());
		if (response.getStatusCode() != HTTPResponse.SC_OK) {
			throw new OAuth2AuthenticationException(
					invalidToken("Introspection endpoint responded with " + response.getStatusCode()));
		}
		return responseEntity.bodyToMono(String.class)
				.doOnNext(response::setContent)
				.map(body -> response);
	}

	private TokenIntrospectionResponse parseNimbusResponse(HTTPResponse response) {
		try {
			return TokenIntrospectionResponse.parse(response);
		} catch (Exception ex) {
			throw new OAuth2AuthenticationException(
					invalidToken(ex.getMessage()), ex);
		}
	}

	private TokenIntrospectionSuccessResponse castToNimbusSuccess(TokenIntrospectionResponse introspectionResponse) {
		if (!introspectionResponse.indicatesSuccess()) {
			throw new OAuth2AuthenticationException(invalidToken("Token introspection failed"));
		}
		return (TokenIntrospectionSuccessResponse) introspectionResponse;
	}

	private void validate(String token, TokenIntrospectionSuccessResponse response) {
		// relying solely on the authorization server to validate this token (not checking 'exp', for example)
		if (!response.isActive()) {
			throw new OAuth2AuthenticationException(invalidToken("Provided token [" + token + "] isn't active"));
		}
	}

	private Map<String, Object> convertClaimsSet(TokenIntrospectionSuccessResponse response) {
		Map<String, Object> claims = response.toJSONObject();
		if (response.getAudience() != null) {
			List<String> audience = response.getAudience().stream()
					.map(Audience::getValue).collect(Collectors.toList());
			claims.put(AUDIENCE, Collections.unmodifiableList(audience));
		}
		if (response.getClientID() != null) {
			claims.put(CLIENT_ID, response.getClientID().getValue());
		}
		if (response.getExpirationTime() != null) {
			Instant exp = response.getExpirationTime().toInstant();
			claims.put(EXPIRES_AT, exp);
		}
		if (response.getIssueTime() != null) {
			Instant iat = response.getIssueTime().toInstant();
			claims.put(ISSUED_AT, iat);
		}
		if (response.getIssuer() != null) {
			claims.put(ISSUER, issuer(response.getIssuer().getValue()));
		}
		if (response.getNotBeforeTime() != null) {
			claims.put(NOT_BEFORE, response.getNotBeforeTime().toInstant());
		}
		if (response.getScope() != null) {
			claims.put(SCOPE, Collections.unmodifiableList(response.getScope().toStringList()));
		}

		return claims;
	}

	private Collection<GrantedAuthority> extractAuthorities(Map<String, Object> claims) {
		Collection<String> scopes = (Collection<String>) claims.get(SCOPE);
		return Optional.ofNullable(scopes).orElse(Collections.emptyList())
				.stream()
				.map(authority -> new SimpleGrantedAuthority("SCOPE_" + authority))
				.collect(Collectors.toList());
	}

	private URL issuer(String uri) {
		try {
			return new URL(uri);
		} catch (Exception ex) {
			throw new OAuth2AuthenticationException(
					invalidToken("Invalid " + ISSUER + " value: " + uri), ex);
		}
	}

	private static BearerTokenError invalidToken(String message) {
		return new BearerTokenError("invalid_token",
				HttpStatus.UNAUTHORIZED, message,
				"https://tools.ietf.org/html/rfc7662#section-2.2");
	}


	private OAuth2AuthenticationException onError(Throwable e) {
		OAuth2Error invalidToken = invalidToken(e.getMessage());
		return new OAuth2AuthenticationException(invalidToken, e.getMessage());
	}
}
