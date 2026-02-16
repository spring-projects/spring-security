/*
 * Copyright 2004-present the original author or authors.
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

import java.io.Serial;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

/**
 * A Spring implementation of {@link OpaqueTokenIntrospector} that verifies and
 * introspects a token using the configured
 * <a href="https://tools.ietf.org/html/rfc7662" target="_blank">OAuth 2.0 Introspection
 * Endpoint</a>, using {@link RestClient} for HTTP communication.
 *
 * @author Andrey Litvitski
 * @since 7.1
 */
public class RestClientSpringOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

	private static final String AUTHORITY_PREFIX = "SCOPE_";

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
	};

	private final Log logger = LogFactory.getLog(getClass());

	private final RestClient restClient;

	private Converter<String, RequestEntity<?>> requestEntityConverter;

	private Converter<OAuth2TokenIntrospectionClaimAccessor, ? extends OAuth2AuthenticatedPrincipal> authenticationConverter = this::defaultAuthenticationConverter;

	/**
	 * Creates a {@code OpaqueTokenAuthenticationProvider} with the provided parameters
	 * The given {@link RestClient} should perform its own client authentication against
	 * the introspection endpoint.
	 * @param introspectionUri The introspection endpoint uri
	 * @param restClient The client for performing the introspection request
	 */
	public RestClientSpringOpaqueTokenIntrospector(String introspectionUri, RestClient restClient) {
		Assert.notNull(introspectionUri, "introspectionUri cannot be null");
		Assert.notNull(restClient, "restClient cannot be null");
		this.requestEntityConverter = this.defaultRequestEntityConverter(URI.create(introspectionUri));
		this.restClient = restClient;
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
		ResponseEntity<Map<String, Object>> responseEntity = makeRequest(requestEntity);
		Map<String, Object> claims = adaptToNimbusResponse(responseEntity);
		OAuth2TokenIntrospectionClaimAccessor accessor = convertClaimsSet(claims);
		return this.authenticationConverter.convert(accessor);
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

	private ResponseEntity<Map<String, Object>> makeRequest(RequestEntity<?> requestEntity) {
		try {
			RestClient.RequestBodySpec spec = this.restClient.method(requestEntity.getMethod())
				.uri(requestEntity.getUrl())
				.headers((headers) -> headers.addAll(requestEntity.getHeaders()));
			return spec.body(requestEntity.getBody()).retrieve().toEntity(STRING_OBJECT_MAP);
		}
		catch (Exception ex) {
			throw new OAuth2IntrospectionException(ex.getMessage(), ex);
		}
	}

	private Map<String, Object> adaptToNimbusResponse(ResponseEntity<Map<String, Object>> responseEntity) {
		if (responseEntity.getStatusCode() != HttpStatus.OK) {
			throw new OAuth2IntrospectionException(
					"Introspection endpoint responded with " + responseEntity.getStatusCode());
		}
		Map<String, Object> claims = responseEntity.getBody();
		// relying solely on the authorization server to validate this token (not checking
		// 'exp', for example)
		if (claims == null) {
			return Collections.emptyMap();
		}

		boolean active = (boolean) claims.compute(OAuth2TokenIntrospectionClaimNames.ACTIVE, (k, v) -> {
			if (v instanceof String) {
				return Boolean.parseBoolean((String) v);
			}
			if (v instanceof Boolean) {
				return v;
			}
			return false;
		});
		if (!active) {
			this.logger.trace("Did not validate token since it is inactive");
			throw new BadOpaqueTokenException("Provided token isn't active");
		}
		return claims;
	}

	private ArrayListFromStringClaimAccessor convertClaimsSet(Map<String, Object> claims) {
		Map<String, Object> converted = new LinkedHashMap<>(claims);
		converted.computeIfPresent(OAuth2TokenIntrospectionClaimNames.AUD, (k, v) -> {
			if (v instanceof String) {
				return Collections.singletonList(v);
			}
			return v;
		});
		converted.computeIfPresent(OAuth2TokenIntrospectionClaimNames.CLIENT_ID, (k, v) -> v.toString());
		converted.computeIfPresent(OAuth2TokenIntrospectionClaimNames.EXP,
				(k, v) -> Instant.ofEpochSecond(((Number) v).longValue()));
		converted.computeIfPresent(OAuth2TokenIntrospectionClaimNames.IAT,
				(k, v) -> Instant.ofEpochSecond(((Number) v).longValue()));
		// RFC-7662 page 7 directs users to RFC-7519 for defining the values of these
		// issuer fields.
		// https://datatracker.ietf.org/doc/html/rfc7662#page-7
		//
		// RFC-7519 page 9 defines issuer fields as being 'case-sensitive' strings
		// containing
		// a 'StringOrURI', which is defined on page 5 as being any string, but strings
		// containing ':'
		// should be treated as valid URIs.
		// https://datatracker.ietf.org/doc/html/rfc7519#section-2
		//
		// It is not defined however as to whether-or-not normalized URIs should be
		// treated as the same literal
		// value. It only defines validation itself, so to avoid potential ambiguity or
		// unwanted side effects that
		// may be awkward to debug, we do not want to manipulate this value. Previous
		// versions of Spring Security
		// would *only* allow valid URLs, which is not what we wish to achieve here.
		converted.computeIfPresent(OAuth2TokenIntrospectionClaimNames.ISS, (k, v) -> v.toString());
		converted.computeIfPresent(OAuth2TokenIntrospectionClaimNames.NBF,
				(k, v) -> Instant.ofEpochSecond(((Number) v).longValue()));
		converted.computeIfPresent(OAuth2TokenIntrospectionClaimNames.SCOPE,
				(k, v) -> (v instanceof String s) ? new ArrayListFromString(s.split(" ")) : v);
		return () -> converted;
	}

	/**
	 * <p>
	 * Sets the {@link Converter Converter&lt;OAuth2TokenIntrospectionClaimAccessor,
	 * OAuth2AuthenticatedPrincipal&gt;} to use. Defaults to
	 * {@link RestClientSpringOpaqueTokenIntrospector#defaultAuthenticationConverter}.
	 * </p>
	 * <p>
	 * Use if you need a custom mapping of OAuth 2.0 token claims to the authenticated
	 * principal.
	 * </p>
	 * @param authenticationConverter the converter
	 * @since 7.1
	 */
	public void setAuthenticationConverter(
			Converter<OAuth2TokenIntrospectionClaimAccessor, ? extends OAuth2AuthenticatedPrincipal> authenticationConverter) {
		Assert.notNull(authenticationConverter, "converter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	/**
	 * If {@link RestClientSpringOpaqueTokenIntrospector#authenticationConverter} is not
	 * explicitly set, this default converter will be used. transforms an
	 * {@link OAuth2TokenIntrospectionClaimAccessor} into an
	 * {@link OAuth2AuthenticatedPrincipal} by extracting claims, mapping scopes to
	 * authorities, and creating a principal.
	 * @return {@link Converter Converter&lt;OAuth2TokenIntrospectionClaimAccessor,
	 * OAuth2AuthenticatedPrincipal&gt;}
	 * @since 7.1
	 */
	private OAuth2IntrospectionAuthenticatedPrincipal defaultAuthenticationConverter(
			OAuth2TokenIntrospectionClaimAccessor accessor) {
		Collection<GrantedAuthority> authorities = authorities(accessor.getScopes());
		return new OAuth2IntrospectionAuthenticatedPrincipal(accessor.getClaims(), authorities);
	}

	private Collection<GrantedAuthority> authorities(List<String> scopes) {
		if (!(scopes instanceof ArrayListFromString)) {
			return Collections.emptyList();
		}
		Collection<GrantedAuthority> authorities = new ArrayList<>();
		for (String scope : scopes) {
			authorities.add(new SimpleGrantedAuthority(AUTHORITY_PREFIX + scope));
		}
		return authorities;
	}

	/**
	 * Creates a {@code RestClientSpringOpaqueTokenIntrospector.Builder} with the given
	 * introspection endpoint uri
	 * @param introspectionUri The introspection endpoint uri
	 * @return the {@link RestClientSpringOpaqueTokenIntrospector.Builder}
	 * @since 7.1
	 */
	public static RestClientSpringOpaqueTokenIntrospector.Builder withIntrospectionUri(String introspectionUri) {
		Assert.notNull(introspectionUri, "introspectionUri cannot be null");
		return new RestClientSpringOpaqueTokenIntrospector.Builder(introspectionUri);
	}

	// gh-7563
	private static final class ArrayListFromString extends ArrayList<String> {

		@Serial
		private static final long serialVersionUID = -1804103555781637109L;

		ArrayListFromString(String... elements) {
			super(Arrays.asList(elements));
		}

	}

	// gh-15165
	private interface ArrayListFromStringClaimAccessor extends OAuth2TokenIntrospectionClaimAccessor {

		@Override
		default List<String> getScopes() {
			Object value = getClaims().get(OAuth2TokenIntrospectionClaimNames.SCOPE);
			if (value instanceof ArrayListFromString list) {
				return list;
			}
			return OAuth2TokenIntrospectionClaimAccessor.super.getScopes();
		}

	}

	/**
	 * Used to build {@link RestClientSpringOpaqueTokenIntrospector}.
	 *
	 * @author Andrey Litvitski
	 * @since 7.1
	 */
	public static final class Builder {

		private final String introspectionUri;

		private String clientId;

		private String clientSecret;

		private Builder(String introspectionUri) {
			this.introspectionUri = introspectionUri;
		}

		/**
		 * The builder will {@link URLEncoder encode} the client id that you provide, so
		 * please give the unencoded value.
		 * @param clientId The unencoded client id
		 * @return the {@link RestClientSpringOpaqueTokenIntrospector.Builder}
		 * @since 7.1
		 */
		public RestClientSpringOpaqueTokenIntrospector.Builder clientId(String clientId) {
			Assert.notNull(clientId, "clientId cannot be null");
			this.clientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8);
			return this;
		}

		/**
		 * The builder will {@link URLEncoder encode} the client secret that you provide,
		 * so please give the unencoded value.
		 * @param clientSecret The unencoded client secret
		 * @return the {@link RestClientSpringOpaqueTokenIntrospector.Builder}
		 * @since 7.1
		 */
		public RestClientSpringOpaqueTokenIntrospector.Builder clientSecret(String clientSecret) {
			Assert.notNull(clientSecret, "clientSecret cannot be null");
			this.clientSecret = URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
			return this;
		}

		/**
		 * Creates a {@code RestClientSpringOpaqueTokenIntrospector}
		 * @return the {@link RestClientSpringOpaqueTokenIntrospector}
		 * @since 7.1
		 */
		public RestClientSpringOpaqueTokenIntrospector build() {
			RestClient restClient = RestClient.builder()
				.defaultHeaders((headers) -> headers.setBasicAuth(this.clientId, this.clientSecret))
				.build();
			return new RestClientSpringOpaqueTokenIntrospector(this.introspectionUri, restClient);
		}

	}

}
