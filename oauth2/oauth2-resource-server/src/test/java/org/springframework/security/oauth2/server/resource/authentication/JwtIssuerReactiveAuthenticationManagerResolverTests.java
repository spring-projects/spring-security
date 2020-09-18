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

package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import net.minidev.json.JSONObject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Test;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link JwtIssuerReactiveAuthenticationManagerResolver}
 */
public class JwtIssuerReactiveAuthenticationManagerResolverTests {

	// @formatter:off
	private static final String DEFAULT_RESPONSE_TEMPLATE = "{\n"
			+ "    \"issuer\": \"%s\", \n"
			+ "    \"jwks_uri\": \"%s/.well-known/jwks.json\" \n"
			+ "}";
	// @formatter:on

	private static final String JWK_SET = "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"one\",\"n\":\"oXJ8OyOv_eRnce4akdanR4KYRfnC2zLV4uYNQpcFn6oHL0dj7D6kxQmsXoYgJV8ZVDn71KGmuLvolxsDncc2UrhyMBY6DVQVgMSVYaPCTgW76iYEKGgzTEw5IBRQL9w3SRJWd3VJTZZQjkXef48Ocz06PGF3lhbz4t5UEZtdF4rIe7u-977QwHuh7yRPBQ3sII-cVoOUMgaXB9SHcGF2iZCtPzL_IffDUcfhLQteGebhW8A6eUHgpD5A1PQ-JCw_G7UOzZAjjDjtNM2eqm8j-Ms_gqnm4MiCZ4E-9pDN77CAAPVN7kuX6ejs9KBXpk01z48i9fORYk9u7rAkh1HuQw\"}]}";

	private String jwt = jwt("iss", "trusted");

	private String evil = jwt("iss", "\"");

	private String noIssuer = jwt("sub", "sub");

	@Test
	public void resolveWhenUsingTrustedIssuerThenReturnsAuthenticationManager() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			String issuer = server.url("").toString();
			server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
					.setBody(String.format(DEFAULT_RESPONSE_TEMPLATE, issuer, issuer)));
			server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
					.setBody(JWK_SET));
			JWSObject jws = new JWSObject(new JWSHeader(JWSAlgorithm.RS256),
					new Payload(new JSONObject(Collections.singletonMap(JwtClaimNames.ISS, issuer))));
			jws.sign(new RSASSASigner(TestKeys.DEFAULT_PRIVATE_KEY));
			JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
					issuer);
			MockServerWebExchange exchange = withBearerToken(jws.serialize());
			ReactiveAuthenticationManager authenticationManager = authenticationManagerResolver.resolve(exchange)
					.block();
			assertThat(authenticationManager).isNotNull();
			ReactiveAuthenticationManager cachedAuthenticationManager = authenticationManagerResolver.resolve(exchange)
					.block();
			assertThat(authenticationManager).isSameAs(cachedAuthenticationManager);
		}
	}

	@Test
	public void resolveWhenUsingUntrustedIssuerThenException() {
		JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
				"other", "issuers");
		MockServerWebExchange exchange = withBearerToken(this.jwt);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(exchange).block())
				.withMessageContaining("Invalid issuer");
		// @formatter:on
	}

	@Test
	public void resolveWhenUsingCustomIssuerAuthenticationManagerResolverThenUses() {
		ReactiveAuthenticationManager authenticationManager = mock(ReactiveAuthenticationManager.class);
		JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
				(issuer) -> Mono.just(authenticationManager));
		MockServerWebExchange exchange = withBearerToken(this.jwt);
		assertThat(authenticationManagerResolver.resolve(exchange).block()).isSameAs(authenticationManager);
	}

	@Test
	public void resolveWhenUsingExternalSourceThenRespondsToChanges() {
		MockServerWebExchange exchange = withBearerToken(this.jwt);
		Map<String, ReactiveAuthenticationManager> authenticationManagers = new HashMap<>();
		JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
				(issuer) -> Mono.justOrEmpty(authenticationManagers.get(issuer)));
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(exchange).block())
				.withMessageContaining("Invalid issuer");
		ReactiveAuthenticationManager authenticationManager = mock(ReactiveAuthenticationManager.class);
		authenticationManagers.put("trusted", authenticationManager);
		assertThat(authenticationManagerResolver.resolve(exchange).block()).isSameAs(authenticationManager);
		authenticationManagers.clear();
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(exchange).block())
				.withMessageContaining("Invalid issuer");
		// @formatter:on
	}

	@Test
	public void resolveWhenBearerTokenMalformedThenException() {
		JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
				"trusted");
		MockServerWebExchange exchange = withBearerToken("jwt");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(exchange).block())
				.withMessageNotContaining("Invalid issuer");
		// @formatter:on
	}

	@Test
	public void resolveWhenBearerTokenNoIssuerThenException() {
		JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
				"trusted");
		MockServerWebExchange exchange = withBearerToken(this.noIssuer);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(exchange).block())
				.withMessageContaining("Missing issuer");
	}

	@Test
	public void resolveWhenBearerTokenEvilThenGenericException() {
		JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
				"trusted");
		MockServerWebExchange exchange = withBearerToken(this.evil);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(exchange).block())
				.withMessage("Invalid token");
		// @formatter:on
	}

	@Test
	public void constructorWhenNullOrEmptyIssuersThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JwtIssuerReactiveAuthenticationManagerResolver((Collection) null));
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JwtIssuerReactiveAuthenticationManagerResolver(Collections.emptyList()));
	}

	@Test
	public void constructorWhenNullAuthenticationManagerResolverThenException() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> new JwtIssuerReactiveAuthenticationManagerResolver((ReactiveAuthenticationManagerResolver) null));
	}

	private String jwt(String claim, String value) {
		PlainJWT jwt = new PlainJWT(new JWTClaimsSet.Builder().claim(claim, value).build());
		return jwt.serialize();
	}

	private MockServerWebExchange withBearerToken(String token) {
		// @formatter:off
		MockServerHttpRequest request = MockServerHttpRequest.get("/")
				.header("Authorization", "Bearer " + token)
				.build();
		// @formatter:on
		return MockServerWebExchange.from(request);
	}

}
