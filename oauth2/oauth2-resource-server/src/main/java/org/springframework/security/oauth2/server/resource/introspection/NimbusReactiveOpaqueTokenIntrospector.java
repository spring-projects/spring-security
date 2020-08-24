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

package org.springframework.security.oauth2.server.resource.introspection;

import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import reactor.core.publisher.Mono;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * A Nimbus implementation of {@link ReactiveOpaqueTokenIntrospector} that verifies and
 * introspects a token using the configured
 * <a href="https://tools.ietf.org/html/rfc7662" target="_blank">OAuth 2.0 Introspection
 * Endpoint</a>.
 *
 * @author Josh Cummings
 * @since 5.2
 */
public class NimbusReactiveOpaqueTokenIntrospector implements ReactiveOpaqueTokenIntrospector {

	private final URI introspectionUri;

	private final WebClient webClient;

	private String authorityPrefix = "SCOPE_";

	/**
	 * Creates a {@code OpaqueTokenReactiveAuthenticationManager} with the provided
	 * parameters
	 * @param introspectionUri The introspection endpoint uri
	 * @param clientId The client id authorized to introspect
	 * @param clientSecret The client secret for the authorized client
	 */
	public NimbusReactiveOpaqueTokenIntrospector(String introspectionUri, String clientId, String clientSecret) {
		Assert.hasText(introspectionUri, "introspectionUri cannot be empty");
		Assert.hasText(clientId, "clientId cannot be empty");
		Assert.notNull(clientSecret, "clientSecret cannot be null");
		this.introspectionUri = URI.create(introspectionUri);
		this.webClient = WebClient.builder().defaultHeaders((h) -> h.setBasicAuth(clientId, clientSecret)).build();
	}

	/**
	 * Creates a {@code OpaqueTokenReactiveAuthenticationManager} with the provided
	 * parameters
	 * @param introspectionUri The introspection endpoint uri
	 * @param webClient The client for performing the introspection request
	 */
	public NimbusReactiveOpaqueTokenIntrospector(String introspectionUri, WebClient webClient) {
		Assert.hasText(introspectionUri, "introspectionUri cannot be null");
		Assert.notNull(webClient, "webClient cannot be null");
		this.introspectionUri = URI.create(introspectionUri);
		this.webClient = webClient;
	}

	@Override
	public Mono<OAuth2AuthenticatedPrincipal> introspect(String token) {
		// @formatter:off
		return Mono.just(token)
				.flatMap(this::makeRequest)
				.flatMap(this::adaptToNimbusResponse)
				.map(this::parseNimbusResponse)
				.map(this::castToNimbusSuccess)
				.doOnNext((response) -> validate(token, response))
				.map(this::convertClaimsSet)
				.onErrorMap((e) -> !(e instanceof OAuth2IntrospectionException), this::onError);
		// @formatter:on
	}

	private Mono<ClientResponse> makeRequest(String token) {
		// @formatter:off
		return this.webClient.post()
				.uri(this.introspectionUri)
				.header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_UTF8_VALUE)
				.body(BodyInserters.fromFormData("token", token))
				.exchange();
		// @formatter:on
	}

	private Mono<HTTPResponse> adaptToNimbusResponse(ClientResponse responseEntity) {
		HTTPResponse response = new HTTPResponse(responseEntity.rawStatusCode());
		response.setHeader(HttpHeaders.CONTENT_TYPE, responseEntity.headers().contentType().get().toString());
		if (response.getStatusCode() != HTTPResponse.SC_OK) {
			// @formatter:off
			return responseEntity.bodyToFlux(DataBuffer.class)
					.map(DataBufferUtils::release)
					.then(Mono.error(new OAuth2IntrospectionException(
							"Introspection endpoint responded with " + response.getStatusCode()))
					);
			// @formatter:on
		}
		return responseEntity.bodyToMono(String.class).doOnNext(response::setContent).map((body) -> response);
	}

	private TokenIntrospectionResponse parseNimbusResponse(HTTPResponse response) {
		try {
			return TokenIntrospectionResponse.parse(response);
		}
		catch (Exception ex) {
			throw new OAuth2IntrospectionException(ex.getMessage(), ex);
		}
	}

	private TokenIntrospectionSuccessResponse castToNimbusSuccess(TokenIntrospectionResponse introspectionResponse) {
		if (!introspectionResponse.indicatesSuccess()) {
			throw new OAuth2IntrospectionException("Token introspection failed");
		}
		return (TokenIntrospectionSuccessResponse) introspectionResponse;
	}

	private void validate(String token, TokenIntrospectionSuccessResponse response) {
		// relying solely on the authorization server to validate this token (not checking
		// 'exp', for example)
		if (!response.isActive()) {
			throw new BadOpaqueTokenException("Provided token isn't active");
		}
	}

	private OAuth2AuthenticatedPrincipal convertClaimsSet(TokenIntrospectionSuccessResponse response) {
		Map<String, Object> claims = response.toJSONObject();
		Collection<GrantedAuthority> authorities = new ArrayList<>();
		if (response.getAudience() != null) {
			List<String> audiences = new ArrayList<>();
			for (Audience audience : response.getAudience()) {
				audiences.add(audience.getValue());
			}
			claims.put(OAuth2IntrospectionClaimNames.AUDIENCE, Collections.unmodifiableList(audiences));
		}
		if (response.getClientID() != null) {
			claims.put(OAuth2IntrospectionClaimNames.CLIENT_ID, response.getClientID().getValue());
		}
		if (response.getExpirationTime() != null) {
			Instant exp = response.getExpirationTime().toInstant();
			claims.put(OAuth2IntrospectionClaimNames.EXPIRES_AT, exp);
		}
		if (response.getIssueTime() != null) {
			Instant iat = response.getIssueTime().toInstant();
			claims.put(OAuth2IntrospectionClaimNames.ISSUED_AT, iat);
		}
		if (response.getIssuer() != null) {
			claims.put(OAuth2IntrospectionClaimNames.ISSUER, issuer(response.getIssuer().getValue()));
		}
		if (response.getNotBeforeTime() != null) {
			claims.put(OAuth2IntrospectionClaimNames.NOT_BEFORE, response.getNotBeforeTime().toInstant());
		}
		if (response.getScope() != null) {
			List<String> scopes = Collections.unmodifiableList(response.getScope().toStringList());
			claims.put(OAuth2IntrospectionClaimNames.SCOPE, scopes);

			for (String scope : scopes) {
				authorities.add(new SimpleGrantedAuthority(this.authorityPrefix + scope));
			}
		}
		return new OAuth2IntrospectionAuthenticatedPrincipal(claims, authorities);
	}

	private URL issuer(String uri) {
		try {
			return new URL(uri);
		}
		catch (Exception ex) {
			throw new OAuth2IntrospectionException(
					"Invalid " + OAuth2IntrospectionClaimNames.ISSUER + " value: " + uri);
		}
	}

	private OAuth2IntrospectionException onError(Throwable ex) {
		return new OAuth2IntrospectionException(ex.getMessage(), ex);
	}

}
