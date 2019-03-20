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
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.AUDIENCE;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.CLIENT_ID;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.EXPIRES_AT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.ISSUED_AT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.ISSUER;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.NOT_BEFORE;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.SCOPE;

/**
 * A Nimbus implementation of {@link ReactiveOAuth2TokenIntrospectionClient}
 *
 * @author Josh Cummings
 * @since 5.2
 */
public class NimbusReactiveOAuth2TokenIntrospectionClient implements ReactiveOAuth2TokenIntrospectionClient {
	private URI introspectionUri;
	private WebClient webClient;

	/**
	 * Creates a {@code OAuth2IntrospectionReactiveAuthenticationManager} with the provided parameters
	 *
	 * @param introspectionUri The introspection endpoint uri
	 * @param clientId The client id authorized to introspect
	 * @param clientSecret The client secret for the authorized client
	 */
	public NimbusReactiveOAuth2TokenIntrospectionClient(String introspectionUri, String clientId, String clientSecret) {
		Assert.hasText(introspectionUri, "introspectionUri cannot be empty");
		Assert.hasText(clientId, "clientId cannot be empty");
		Assert.notNull(clientSecret, "clientSecret cannot be null");

		this.introspectionUri = URI.create(introspectionUri);
		this.webClient = WebClient.builder()
				.defaultHeaders(h -> h.setBasicAuth(clientId, clientSecret))
				.build();
	}

	/**
	 * Creates a {@code OAuth2IntrospectionReactiveAuthenticationManager} with the provided parameters
	 *
	 * @param introspectionUri The introspection endpoint uri
	 * @param webClient The client for performing the introspection request
	 */
	public NimbusReactiveOAuth2TokenIntrospectionClient(String introspectionUri, WebClient webClient) {
		Assert.hasText(introspectionUri, "introspectionUri cannot be null");
		Assert.notNull(webClient, "webClient cannot be null");

		this.introspectionUri = URI.create(introspectionUri);
		this.webClient = webClient;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Mono<Map<String, Object>> introspect(String token) {
		return Mono.just(token)
				.flatMap(this::makeRequest)
				.flatMap(this::adaptToNimbusResponse)
				.map(this::parseNimbusResponse)
				.map(this::castToNimbusSuccess)
				.doOnNext(response -> validate(token, response))
				.map(this::convertClaimsSet)
				.onErrorMap(e -> !(e instanceof OAuth2IntrospectionException), this::onError);
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
			throw new OAuth2IntrospectionException(
					"Introspection endpoint responded with " + response.getStatusCode());
		}
		return responseEntity.bodyToMono(String.class)
				.doOnNext(response::setContent)
				.map(body -> response);
	}

	private TokenIntrospectionResponse parseNimbusResponse(HTTPResponse response) {
		try {
			return TokenIntrospectionResponse.parse(response);
		} catch (Exception ex) {
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
		// relying solely on the authorization server to validate this token (not checking 'exp', for example)
		if (!response.isActive()) {
			throw new OAuth2IntrospectionException("Provided token [" + token + "] isn't active");
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

	private URL issuer(String uri) {
		try {
			return new URL(uri);
		} catch (Exception ex) {
			throw new OAuth2IntrospectionException("Invalid " + ISSUER + " value: " + uri);
		}
	}

	private OAuth2IntrospectionException onError(Throwable e) {
		return new OAuth2IntrospectionException(e.getMessage(), e);
	}
}
