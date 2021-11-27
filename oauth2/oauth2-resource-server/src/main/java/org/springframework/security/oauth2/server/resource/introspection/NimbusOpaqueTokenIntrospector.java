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

package org.springframework.security.oauth2.server.resource.introspection;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * A Nimbus implementation of {@link OpaqueTokenIntrospector} that verifies and
 * introspects a token using the configured
 * <a href="https://tools.ietf.org/html/rfc7662" target="_blank">OAuth 2.0 Introspection
 * Endpoint</a>.
 *
 * @author Josh Cummings
 * @author MD Sayem Ahmed
 * @since 5.2
 */
public class NimbusOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

	private static final String AUTHORITY_PREFIX = "SCOPE_";

	private final Log logger = LogFactory.getLog(getClass());

	private final RestOperations restOperations;

	private Converter<String, RequestEntity<?>> requestEntityConverter;

	/**
	 * Creates a {@code OpaqueTokenAuthenticationProvider} with the provided parameters
	 * @param introspectionUri The introspection endpoint uri
	 * @param clientId The client id authorized to introspect
	 * @param clientSecret The client's secret
	 */
	public NimbusOpaqueTokenIntrospector(String introspectionUri, String clientId, String clientSecret) {
		Assert.notNull(introspectionUri, "introspectionUri cannot be null");
		Assert.notNull(clientId, "clientId cannot be null");
		Assert.notNull(clientSecret, "clientSecret cannot be null");
		this.requestEntityConverter = this.defaultRequestEntityConverter(URI.create(introspectionUri));
		RestTemplate restTemplate = new RestTemplate();
		restTemplate.getInterceptors().add(new BasicAuthenticationInterceptor(clientId, clientSecret));
		this.restOperations = restTemplate;
	}

	/**
	 * Creates a {@code OpaqueTokenAuthenticationProvider} with the provided parameters
	 *
	 * The given {@link RestOperations} should perform its own client authentication
	 * against the introspection endpoint.
	 * @param introspectionUri The introspection endpoint uri
	 * @param restOperations The client for performing the introspection request
	 */
	public NimbusOpaqueTokenIntrospector(String introspectionUri, RestOperations restOperations) {
		Assert.notNull(introspectionUri, "introspectionUri cannot be null");
		Assert.notNull(restOperations, "restOperations cannot be null");
		this.requestEntityConverter = this.defaultRequestEntityConverter(URI.create(introspectionUri));
		this.restOperations = restOperations;
	}

	private Converter<String, RequestEntity<?>> defaultRequestEntityConverter(URI introspectionUri) {
		return (token) -> {
			HttpHeaders headers = requestHeaders();
			MultiValueMap<String, String> body = requestBody(token);
			return new RequestEntity<>(body, headers, HttpMethod.POST, introspectionUri);
		};
	}

	private HttpHeaders requestHeaders() {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
		return headers;
	}

	private MultiValueMap<String, String> requestBody(String token) {
		MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
		body.add("token", token);
		return body;
	}

	@Override
	public OAuth2AuthenticatedPrincipal introspect(String token) {
		RequestEntity<?> requestEntity = this.requestEntityConverter.convert(token);
		if (requestEntity == null) {
			throw new OAuth2IntrospectionException("requestEntityConverter returned a null entity");
		}
		ResponseEntity<String> responseEntity = makeRequest(requestEntity);
		HTTPResponse httpResponse = adaptToNimbusResponse(responseEntity);
		TokenIntrospectionResponse introspectionResponse = parseNimbusResponse(httpResponse);
		TokenIntrospectionSuccessResponse introspectionSuccessResponse = castToNimbusSuccess(introspectionResponse);
		// relying solely on the authorization server to validate this token (not checking
		// 'exp', for example)
		if (!introspectionSuccessResponse.isActive()) {
			this.logger.trace("Did not validate token since it is inactive");
			throw new BadOpaqueTokenException("Provided token isn't active");
		}
		return convertClaimsSet(introspectionSuccessResponse);
	}

	/**
	 * Sets the {@link Converter} used for converting the OAuth 2.0 access token to a
	 * {@link RequestEntity} representation of the OAuth 2.0 token introspection request.
	 * @param requestEntityConverter the {@link Converter} used for converting to a
	 * {@link RequestEntity} representation of the token introspection request
	 */
	public void setRequestEntityConverter(Converter<String, RequestEntity<?>> requestEntityConverter) {
		Assert.notNull(requestEntityConverter, "requestEntityConverter cannot be null");
		this.requestEntityConverter = requestEntityConverter;
	}

	private ResponseEntity<String> makeRequest(RequestEntity<?> requestEntity) {
		try {
			return this.restOperations.exchange(requestEntity, String.class);
		}
		catch (Exception ex) {
			throw new OAuth2IntrospectionException(ex.getMessage(), ex);
		}
	}

	private HTTPResponse adaptToNimbusResponse(ResponseEntity<String> responseEntity) {
		MediaType contentType = responseEntity.getHeaders().getContentType();

		if (contentType == null) {
			this.logger.trace("Did not receive Content-Type from introspection endpoint in response");

			throw new OAuth2IntrospectionException(
					"Introspection endpoint response was invalid, as no Content-Type header was provided");
		}

		// Nimbus expects JSON, but does not appear to validate this header first.
		if (!contentType.isCompatibleWith(MediaType.APPLICATION_JSON)) {
			this.logger.trace("Did not receive JSON-compatible Content-Type from introspection endpoint in response");

			throw new OAuth2IntrospectionException("Introspection endpoint response was invalid, as content type '"
					+ contentType + "' is not compatible with JSON");
		}

		HTTPResponse response = new HTTPResponse(responseEntity.getStatusCodeValue());
		response.setHeader(HttpHeaders.CONTENT_TYPE, contentType.toString());
		response.setContent(responseEntity.getBody());

		if (response.getStatusCode() != HTTPResponse.SC_OK) {
			this.logger.trace("Introspection endpoint returned non-OK status code");

			throw new OAuth2IntrospectionException(
					"Introspection endpoint responded with HTTP status code " + response.getStatusCode());
		}
		return response;
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
			ErrorObject errorObject = introspectionResponse.toErrorResponse().getErrorObject();
			String message = "Token introspection failed with response " + errorObject.toJSONObject().toJSONString();
			this.logger.trace(message);
			throw new OAuth2IntrospectionException(message);
		}
		return (TokenIntrospectionSuccessResponse) introspectionResponse;
	}

	private OAuth2AuthenticatedPrincipal convertClaimsSet(TokenIntrospectionSuccessResponse response) {
		Collection<GrantedAuthority> authorities = new ArrayList<>();
		Map<String, Object> claims = response.toJSONObject();
		if (response.getAudience() != null) {
			List<String> audiences = new ArrayList<>();
			for (Audience audience : response.getAudience()) {
				audiences.add(audience.getValue());
			}
			claims.put(OAuth2TokenIntrospectionClaimNames.AUD, Collections.unmodifiableList(audiences));
		}
		if (response.getClientID() != null) {
			claims.put(OAuth2TokenIntrospectionClaimNames.CLIENT_ID, response.getClientID().getValue());
		}
		if (response.getExpirationTime() != null) {
			Instant exp = response.getExpirationTime().toInstant();
			claims.put(OAuth2TokenIntrospectionClaimNames.EXP, exp);
		}
		if (response.getIssueTime() != null) {
			Instant iat = response.getIssueTime().toInstant();
			claims.put(OAuth2TokenIntrospectionClaimNames.IAT, iat);
		}
		if (response.getIssuer() != null) {
			// RFC-7662 page 7 directs users to RFC-7519 for defining the values of these
			// issuer fields.
			// https://datatracker.ietf.org/doc/html/rfc7662#page-7
			//
			// RFC-7519 page 9 defines issuer fields as being 'case-sensitive' strings
			// containing
			// a 'StringOrURI', which is defined on page 5 as being any string, but
			// strings containing ':'
			// should be treated as valid URIs.
			// https://datatracker.ietf.org/doc/html/rfc7519#section-2
			//
			// It is not defined however as to whether-or-not normalized URIs should be
			// treated as the same literal
			// value. It only defines validation itself, so to avoid potential ambiguity
			// or unwanted side effects that
			// may be awkward to debug, we do not want to manipulate this value. Previous
			// versions of Spring Security
			// would *only* allow valid URLs, which is not what we wish to achieve here.
			claims.put(OAuth2TokenIntrospectionClaimNames.ISS, response.getIssuer().getValue());
		}
		if (response.getNotBeforeTime() != null) {
			claims.put(OAuth2TokenIntrospectionClaimNames.NBF, response.getNotBeforeTime().toInstant());
		}
		if (response.getScope() != null) {
			List<String> scopes = Collections.unmodifiableList(response.getScope().toStringList());
			claims.put(OAuth2TokenIntrospectionClaimNames.SCOPE, scopes);
			for (String scope : scopes) {
				authorities.add(new SimpleGrantedAuthority(AUTHORITY_PREFIX + scope));
			}
		}
		return new OAuth2IntrospectionAuthenticatedPrincipal(claims, authorities);
	}

}
