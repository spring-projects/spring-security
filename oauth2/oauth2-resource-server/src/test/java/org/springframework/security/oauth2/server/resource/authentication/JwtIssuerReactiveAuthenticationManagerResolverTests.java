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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.ISS;

/**
 * Tests for {@link JwtIssuerReactiveAuthenticationManagerResolver}
 */
public class JwtIssuerReactiveAuthenticationManagerResolverTests {

	private static final String DEFAULT_RESPONSE_TEMPLATE = "{\n" + "    \"issuer\": \"%s\", \n"
			+ "    \"jwks_uri\": \"%s/.well-known/jwks.json\" \n" + "}";

	private String jwt = jwt("iss", "trusted");

	private String evil = jwt("iss", "\"");

	private String noIssuer = jwt("sub", "sub");

	@Test
	public void resolveWhenUsingTrustedIssuerThenReturnsAuthenticationManager() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			String issuer = server.url("").toString();
			server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
					.setBody(String.format(DEFAULT_RESPONSE_TEMPLATE, issuer, issuer)));
			JWSObject jws = new JWSObject(new JWSHeader(JWSAlgorithm.RS256),
					new Payload(new JSONObject(Collections.singletonMap(ISS, issuer))));
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

		assertThatCode(() -> authenticationManagerResolver.resolve(exchange).block())
				.isInstanceOf(OAuth2AuthenticationException.class).hasMessageContaining("Invalid issuer");
	}

	@Test
	public void resolveWhenUsingCustomIssuerAuthenticationManagerResolverThenUses() {
		ReactiveAuthenticationManager authenticationManager = mock(ReactiveAuthenticationManager.class);
		JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
				issuer -> Mono.just(authenticationManager));
		MockServerWebExchange exchange = withBearerToken(this.jwt);

		assertThat(authenticationManagerResolver.resolve(exchange).block()).isSameAs(authenticationManager);
	}

	@Test
	public void resolveWhenUsingExternalSourceThenRespondsToChanges() {
		MockServerWebExchange exchange = withBearerToken(this.jwt);

		Map<String, ReactiveAuthenticationManager> authenticationManagers = new HashMap<>();
		JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
				issuer -> Mono.justOrEmpty(authenticationManagers.get(issuer)));
		assertThatCode(() -> authenticationManagerResolver.resolve(exchange).block())
				.isInstanceOf(OAuth2AuthenticationException.class).hasMessageContaining("Invalid issuer");

		ReactiveAuthenticationManager authenticationManager = mock(ReactiveAuthenticationManager.class);
		authenticationManagers.put("trusted", authenticationManager);
		assertThat(authenticationManagerResolver.resolve(exchange).block()).isSameAs(authenticationManager);

		authenticationManagers.clear();
		assertThatCode(() -> authenticationManagerResolver.resolve(exchange).block())
				.isInstanceOf(OAuth2AuthenticationException.class).hasMessageContaining("Invalid issuer");
	}

	@Test
	public void resolveWhenBearerTokenMalformedThenException() {
		JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
				"trusted");
		MockServerWebExchange exchange = withBearerToken("jwt");
		assertThatCode(() -> authenticationManagerResolver.resolve(exchange).block())
				.isInstanceOf(OAuth2AuthenticationException.class).hasMessageNotContaining("Invalid issuer");
	}

	@Test
	public void resolveWhenBearerTokenNoIssuerThenException() {
		JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
				"trusted");
		MockServerWebExchange exchange = withBearerToken(this.noIssuer);
		assertThatCode(() -> authenticationManagerResolver.resolve(exchange).block())
				.isInstanceOf(OAuth2AuthenticationException.class).hasMessageContaining("Missing issuer");
	}

	@Test
	public void resolveWhenBearerTokenEvilThenGenericException() {
		JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
				"trusted");
		MockServerWebExchange exchange = withBearerToken(this.evil);
		assertThatCode(() -> authenticationManagerResolver.resolve(exchange).block())
				.isInstanceOf(OAuth2AuthenticationException.class).hasMessage("Invalid token");
	}

	@Test
	public void constructorWhenNullOrEmptyIssuersThenException() {
		assertThatCode(() -> new JwtIssuerReactiveAuthenticationManagerResolver((Collection) null))
				.isInstanceOf(IllegalArgumentException.class);
		assertThatCode(() -> new JwtIssuerReactiveAuthenticationManagerResolver(Collections.emptyList()))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenNullAuthenticationManagerResolverThenException() {
		assertThatCode(
				() -> new JwtIssuerReactiveAuthenticationManagerResolver((ReactiveAuthenticationManagerResolver) null))
						.isInstanceOf(IllegalArgumentException.class);
	}

	private String jwt(String claim, String value) {
		PlainJWT jwt = new PlainJWT(new JWTClaimsSet.Builder().claim(claim, value).build());
		return jwt.serialize();
	}

	private MockServerWebExchange withBearerToken(String token) {
		MockServerHttpRequest request = MockServerHttpRequest.get("/").header("Authorization", "Bearer " + token)
				.build();
		return MockServerWebExchange.from(request);
	}

}
