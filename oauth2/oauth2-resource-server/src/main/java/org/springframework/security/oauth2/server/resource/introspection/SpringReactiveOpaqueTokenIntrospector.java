/*
 * Copyright 2002-2025 the original author or authors.
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

import reactor.core.publisher.Mono;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * A Spring implementation of {@link ReactiveOpaqueTokenIntrospector} that verifies and
 * introspects a token using the configured
 * <a href="https://tools.ietf.org/html/rfc7662" target="_blank">OAuth 2.0 Introspection
 * Endpoint</a>.
 *
 * @author Josh Cummings
 * @since 5.6
 */
public class SpringReactiveOpaqueTokenIntrospector implements ReactiveOpaqueTokenIntrospector {

	private static final String AUTHORITY_PREFIX = "SCOPE_";

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
	};

	private final URI introspectionUri;

	private final WebClient webClient;

	private Converter<OAuth2TokenIntrospectionClaimAccessor, Mono<? extends OAuth2AuthenticatedPrincipal>> authenticationConverter = this::defaultAuthenticationConverter;

	/**
	 * Creates a {@code OpaqueTokenReactiveAuthenticationManager} with the provided
	 * parameters
	 * @param introspectionUri The introspection endpoint uri
	 * @param clientId The URL-encoded client id authorized to introspect
	 * @param clientSecret The URL-encoded client secret authorized to introspect
	 * @deprecated Please use {@link SpringReactiveOpaqueTokenIntrospector.Builder}
	 */
	@Deprecated(since = "6.5", forRemoval = true)
	public SpringReactiveOpaqueTokenIntrospector(String introspectionUri, String clientId, String clientSecret) {
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
	public SpringReactiveOpaqueTokenIntrospector(String introspectionUri, WebClient webClient) {
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
				.map(this::convertClaimsSet)
				.flatMap(this.authenticationConverter::convert)
				.cast(OAuth2AuthenticatedPrincipal.class)
				.onErrorMap((e) -> !(e instanceof OAuth2IntrospectionException), this::onError);
		// @formatter:on
	}

	private Mono<ClientResponse> makeRequest(String token) {
		// @formatter:off
		return this.webClient.post()
				.uri(this.introspectionUri)
				.header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
				.body(BodyInserters.fromFormData("token", token))
				.exchange();
		// @formatter:on
	}

	private Mono<Map<String, Object>> adaptToNimbusResponse(ClientResponse responseEntity) {
		if (responseEntity.statusCode() != HttpStatus.OK) {
			// @formatter:off
			return responseEntity.bodyToFlux(DataBuffer.class)
					.map(DataBufferUtils::release)
					.then(Mono.error(new OAuth2IntrospectionException(
							"Introspection endpoint responded with " + responseEntity.statusCode()))
					);
			// @formatter:on
		}
		// relying solely on the authorization server to validate this token (not checking
		// 'exp', for example)
		return responseEntity.bodyToMono(STRING_OBJECT_MAP)
			.filter((body) -> (boolean) body.compute(OAuth2TokenIntrospectionClaimNames.ACTIVE, (k, v) -> {
				if (v instanceof String) {
					return Boolean.parseBoolean((String) v);
				}
				if (v instanceof Boolean) {
					return v;
				}
				return false;
			}))
			.switchIfEmpty(Mono.error(() -> new BadOpaqueTokenException("Provided token isn't active")));
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

	private OAuth2IntrospectionException onError(Throwable ex) {
		return new OAuth2IntrospectionException(ex.getMessage(), ex);
	}

	/**
	 * <p>
	 * Sets the {@link Converter Converter&lt;OAuth2TokenIntrospectionClaimAccessor,
	 * OAuth2AuthenticatedPrincipal&gt;} to use. Defaults to
	 * {@link SpringReactiveOpaqueTokenIntrospector#defaultAuthenticationConverter}.
	 * </p>
	 * <p>
	 * Use if you need a custom mapping of OAuth 2.0 token claims to the authenticated
	 * principal.
	 * </p>
	 * @param authenticationConverter the converter
	 * @since 6.3
	 */
	public void setAuthenticationConverter(
			Converter<OAuth2TokenIntrospectionClaimAccessor, Mono<? extends OAuth2AuthenticatedPrincipal>> authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	private Mono<OAuth2IntrospectionAuthenticatedPrincipal> defaultAuthenticationConverter(
			OAuth2TokenIntrospectionClaimAccessor accessor) {
		Collection<GrantedAuthority> authorities = authorities(accessor.getScopes());
		return Mono.just(new OAuth2IntrospectionAuthenticatedPrincipal(accessor.getClaims(), authorities));
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
	 * Creates a {@code SpringReactiveOpaqueTokenIntrospector.Builder} with the given
	 * introspection endpoint uri
	 * @param introspectionUri The introspection endpoint uri
	 * @return the {@link SpringReactiveOpaqueTokenIntrospector.Builder}
	 * @since 6.5
	 */
	public static Builder withIntrospectionUri(String introspectionUri) {

		return new Builder(introspectionUri);
	}

	// gh-7563
	private static final class ArrayListFromString extends ArrayList<String> {

		@Serial
		private static final long serialVersionUID = 9182779930765511117L;

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
	 * Used to build {@link SpringReactiveOpaqueTokenIntrospector}.
	 *
	 * @author Ngoc Nhan
	 * @since 6.5
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
		 * @return the {@link SpringReactiveOpaqueTokenIntrospector.Builder}
		 * @since 6.5
		 */
		public Builder clientId(String clientId) {
			Assert.notNull(clientId, "clientId cannot be null");
			this.clientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8);
			return this;
		}

		/**
		 * The builder will {@link URLEncoder encode} the client secret that you provide,
		 * so please give the unencoded value.
		 * @param clientSecret The unencoded client secret
		 * @return the {@link SpringReactiveOpaqueTokenIntrospector.Builder}
		 * @since 6.5
		 */
		public Builder clientSecret(String clientSecret) {
			Assert.notNull(clientSecret, "clientSecret cannot be null");
			this.clientSecret = URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
			return this;
		}

		/**
		 * Creates a {@code SpringReactiveOpaqueTokenIntrospector}
		 * @return the {@link SpringReactiveOpaqueTokenIntrospector}
		 * @since 6.5
		 */
		public SpringReactiveOpaqueTokenIntrospector build() {
			WebClient webClient = WebClient.builder()
				.defaultHeaders((h) -> h.setBasicAuth(this.clientId, this.clientSecret))
				.build();
			return new SpringReactiveOpaqueTokenIntrospector(this.introspectionUri, webClient);
		}

	}

}
