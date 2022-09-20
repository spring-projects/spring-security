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
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver.TrustedIssuerJwtAuthenticationManagerResolver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.mock;
import static org.mockito.BDDMockito.verify;

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

	private static final String JWK_SET = "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"one\",\"n\":\"3FlqJr5TRskIQIgdE3Dd7D9lboWdcTUT8a-fJR7MAvQm7XXNoYkm3v7MQL1NYtDvL2l8CAnc0WdSTINU6IRvc5Kqo2Q4csNX9SHOmEfzoROjQqahEcve1jBXluoCXdYuYpx4_1tfRgG6ii4Uhxh6iI8qNMJQX-fLfqhbfYfxBQVRPywBkAbIP4x1EAsbC6FSNmkhCxiMNqEgxaIpY8C2kJdJ_ZIV-WW4noDdzpKqHcwmB8FsrumlVY_DNVvUSDIipiq9PbP4H99TXN1o746oRaNa07rq1hoCgMSSy-85SagCoxlmyE-D-of9SsMY8Ol9t0rdzpobBuhyJ_o5dfvjKw\"}]}";

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
			server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
					.setBody(JWK_SET));
			JWSObject jws = new JWSObject(new JWSHeader(JWSAlgorithm.RS256),
					new Payload(new JSONObject(Collections.singletonMap(JwtClaimNames.ISS, issuer))));
			jws.sign(new RSASSASigner(TestKeys.DEFAULT_PRIVATE_KEY));
			JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
					issuer);
			ReactiveAuthenticationManager authenticationManager = authenticationManagerResolver.resolve(null).block();
			assertThat(authenticationManager).isNotNull();
			BearerTokenAuthenticationToken token = withBearerToken(jws.serialize());
			Authentication authentication = authenticationManager.authenticate(token).block();
			assertThat(authentication).isNotNull();
			assertThat(authentication.isAuthenticated()).isTrue();
		}
	}

	// gh-10444
	@Test
	public void resolveWhednUsingTrustedIssuerThenReturnsAuthenticationManager() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			String issuer = server.url("").toString();
			// @formatter:off
			server.enqueue(new MockResponse().setResponseCode(500).setHeader("Content-Type", "application/json")
					.setBody(String.format(DEFAULT_RESPONSE_TEMPLATE, issuer, issuer)));
			server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
					.setBody(String.format(DEFAULT_RESPONSE_TEMPLATE, issuer, issuer)));
			server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
					.setBody(JWK_SET));
			// @formatter:on
			JWSObject jws = new JWSObject(new JWSHeader(JWSAlgorithm.RS256),
					new Payload(new JSONObject(Collections.singletonMap(JwtClaimNames.ISS, issuer))));
			jws.sign(new RSASSASigner(TestKeys.DEFAULT_PRIVATE_KEY));
			JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
					issuer);
			ReactiveAuthenticationManager authenticationManager = authenticationManagerResolver.resolve(null).block();
			assertThat(authenticationManager).isNotNull();
			Authentication token = withBearerToken(jws.serialize());
			assertThatExceptionOfType(IllegalArgumentException.class)
					.isThrownBy(() -> authenticationManager.authenticate(token).block());
			Authentication authentication = authenticationManager.authenticate(token).block();
			assertThat(authentication.isAuthenticated()).isTrue();
		}
	}

	@Test
	public void resolveWhenUsingSameIssuerThenReturnsSameAuthenticationManager() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			String issuer = server.url("").toString();
			server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
					.setBody(String.format(DEFAULT_RESPONSE_TEMPLATE, issuer, issuer)));
			server.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
					.setBody(JWK_SET));
			TrustedIssuerJwtAuthenticationManagerResolver resolver = new TrustedIssuerJwtAuthenticationManagerResolver(
					(iss) -> iss.equals(issuer));
			ReactiveAuthenticationManager authenticationManager = resolver.resolve(issuer).block();
			ReactiveAuthenticationManager cachedAuthenticationManager = resolver.resolve(issuer).block();
			assertThat(authenticationManager).isSameAs(cachedAuthenticationManager);
		}
	}

	@Test
	public void resolveWhenUsingUntrustedIssuerThenException() {
		JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
				"other", "issuers");
		Authentication token = withBearerToken(this.jwt);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(null)
						.flatMap((authenticationManager) -> authenticationManager.authenticate(token))
						.block())
				.withMessageContaining("Invalid issuer");
		// @formatter:on
	}

	@Test
	public void resolveWhenUsingCustomIssuerAuthenticationManagerResolverThenUses() {
		Authentication token = withBearerToken(this.jwt);
		ReactiveAuthenticationManager authenticationManager = mock(ReactiveAuthenticationManager.class);
		given(authenticationManager.authenticate(token)).willReturn(Mono.empty());
		JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
				(issuer) -> Mono.just(authenticationManager));
		authenticationManagerResolver.resolve(null).flatMap((manager) -> manager.authenticate(token)).block();
		verify(authenticationManager).authenticate(any());
	}

	@Test
	public void resolveWhenUsingExternalSourceThenRespondsToChanges() {
		Authentication token = withBearerToken(this.jwt);
		Map<String, ReactiveAuthenticationManager> authenticationManagers = new HashMap<>();
		JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
				(issuer) -> Mono.justOrEmpty(authenticationManagers.get(issuer)));
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(null)
						.flatMap((manager) -> manager.authenticate(token)).block())
				.withMessageContaining("Invalid issuer");
		ReactiveAuthenticationManager authenticationManager = mock(ReactiveAuthenticationManager.class);
		given(authenticationManager.authenticate(token)).willReturn(Mono.empty());
		authenticationManagers.put("trusted", authenticationManager);
		authenticationManagerResolver.resolve(null).flatMap((manager) -> manager.authenticate(token)).block();
		verify(authenticationManager).authenticate(token);
		authenticationManagers.clear();
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(null)
						.flatMap((manager) -> manager.authenticate(token))
						.block())
				.withMessageContaining("Invalid issuer");
		// @formatter:on
	}

	@Test
	public void resolveWhenBearerTokenMalformedThenException() {
		JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
				"trusted");
		Authentication token = withBearerToken("jwt");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(null)
						.flatMap((manager) -> manager.authenticate(token))
						.block())
				.withMessageNotContaining("Invalid issuer");
		// @formatter:on
	}

	@Test
	public void resolveWhenBearerTokenNoIssuerThenException() {
		JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
				"trusted");
		Authentication token = withBearerToken(this.noIssuer);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(null)
						.flatMap((manager) -> manager.authenticate(token)).block())
				.withMessageContaining("Missing issuer");
	}

	@Test
	public void resolveWhenBearerTokenEvilThenGenericException() {
		JwtIssuerReactiveAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
				"trusted");
		Authentication token = withBearerToken(this.evil);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(null)
						.flatMap((manager) -> manager.authenticate(token))
						.block())
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

	private BearerTokenAuthenticationToken withBearerToken(String token) {
		return new BearerTokenAuthenticationToken(token);
	}

}
