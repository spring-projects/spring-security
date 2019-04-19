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
import java.time.Instant;
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

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.AUDIENCE;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.CLIENT_ID;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.EXPIRES_AT;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.ISSUED_AT;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.ISSUER;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.NOT_BEFORE;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.SCOPE;

/**
 * An {@link AuthenticationProvider} implementation for opaque
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>s,
 * using an
 * <a href="https://tools.ietf.org/html/rfc7662" target="_blank">OAuth 2.0 Introspection Endpoint</a>
 * to check the token's validity and reveal its attributes.
 * <p>
 * This {@link AuthenticationProvider} is responsible for introspecting and verifying an opaque access token,
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
 * @see AuthenticationProvider
 */
public final class OAuth2IntrospectionAuthenticationProvider implements AuthenticationProvider {
	private URI introspectionUri;
	private RestOperations restOperations;

	/**
	 * Creates a {@code OAuth2IntrospectionAuthenticationProvider} with the provided parameters
	 *
	 * @param introspectionUri The introspection endpoint uri
	 * @param clientId The client id authorized to introspect
	 * @param clientSecret The client secret for the authorized client
	 */
	public OAuth2IntrospectionAuthenticationProvider(String introspectionUri, String clientId, String clientSecret) {
		Assert.notNull(introspectionUri, "introspectionUri cannot be null");
		Assert.notNull(clientId, "clientId cannot be null");
		Assert.notNull(clientSecret, "clientSecret cannot be null");

		this.introspectionUri = URI.create(introspectionUri);
		RestTemplate restTemplate = new RestTemplate();
		restTemplate.getInterceptors().add(new BasicAuthenticationInterceptor(clientId, clientSecret));
		this.restOperations = restTemplate;
	}

	/**
	 * Creates a {@code OAuth2IntrospectionAuthenticationProvider} with the provided parameters
	 *
	 * @param introspectionUri The introspection endpoint uri
	 * @param restOperations The client for performing the introspection request
	 */
	public OAuth2IntrospectionAuthenticationProvider(String introspectionUri, RestOperations restOperations) {
		Assert.notNull(introspectionUri, "introspectionUri cannot be null");
		Assert.notNull(restOperations, "restOperations cannot be null");

		this.introspectionUri = URI.create(introspectionUri);
		this.restOperations = restOperations;
	}

	/**
	 * Introspect and validate the opaque
	 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>.
	 *
	 * @param authentication the authentication request object.
	 *
	 * @return A successful authentication
	 * @throws AuthenticationException if authentication failed for some reason
	 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!(authentication instanceof BearerTokenAuthenticationToken)) {
			return null;
		}

		// introspect
		BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken) authentication;
		TokenIntrospectionSuccessResponse response = introspect(bearer.getToken());
		Map<String, Object> claims = convertClaimsSet(response);

		// construct token
		OAuth2AccessToken token  = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				bearer.getToken(), claims);
		Collection<GrantedAuthority> authorities = extractAuthorities(claims);
		AbstractAuthenticationToken result =
				new OAuth2IntrospectionAuthenticationToken(token, authorities);
		result.setDetails(bearer.getDetails());
		return result;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean supports(Class<?> authentication) {
		return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private TokenIntrospectionSuccessResponse introspect(String token) {
		return Optional.of(token)
				.map(this::buildRequest)
				.map(this::makeRequest)
				.map(this::adaptToNimbusResponse)
				.map(this::parseNimbusResponse)
				.map(this::castToNimbusSuccess)
				// relying solely on the authorization server to validate this token (not checking 'exp', for example)
				.filter(TokenIntrospectionSuccessResponse::isActive)
				.orElseThrow(() -> new OAuth2AuthenticationException(
						invalidToken("Provided token [" + token + "] isn't active")));
	}

	private RequestEntity<MultiValueMap<String, String>> buildRequest(String token) {
		HttpHeaders headers = requestHeaders();
		MultiValueMap<String, String> body = requestBody(token);
		return new RequestEntity<>(body, headers, HttpMethod.POST, this.introspectionUri);
	}

	private HttpHeaders requestHeaders() {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON_UTF8));
		return headers;
	}

	private MultiValueMap<String, String> requestBody(String token) {
		MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
		body.add("token", token);
		return body;
	}

	private ResponseEntity<String> makeRequest(RequestEntity<?> requestEntity) {
		try {
			return this.restOperations.exchange(requestEntity, String.class);
		} catch (Exception ex) {
			throw new OAuth2AuthenticationException(
					invalidToken(ex.getMessage()), ex);
		}
	}

	private HTTPResponse adaptToNimbusResponse(ResponseEntity<String> responseEntity) {
		HTTPResponse response = new HTTPResponse(responseEntity.getStatusCodeValue());
		response.setHeader(HttpHeaders.CONTENT_TYPE, responseEntity.getHeaders().getContentType().toString());
		response.setContent(responseEntity.getBody());

		if (response.getStatusCode() != HTTPResponse.SC_OK) {
			throw new OAuth2AuthenticationException(
					invalidToken("Introspection endpoint responded with " + response.getStatusCode()));
		}
		return response;
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
}
