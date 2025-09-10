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

package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Predicate;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.TestJwts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.mock;
import static org.mockito.BDDMockito.verify;
import static org.mockito.Mockito.mockStatic;

/**
 * Tests for {@link JwtIssuerAuthenticationManagerResolver}
 */
public class JwtIssuerAuthenticationManagerResolverTests {

	private String jwt = jwt("iss", "trusted");

	private String evil = jwt("iss", "\"");

	private String noIssuer = jwt("sub", "sub");

	@Test
	public void resolveWhenUsingFromTrustedIssuersThenReturnsAuthenticationManager() throws Exception {
		String issuer = "https://idp.example";

		// @formatter:on
		JWSObject jws = new JWSObject(new JWSHeader(JWSAlgorithm.RS256),
				new Payload(new JSONObject(Collections.singletonMap(JwtClaimNames.ISS, issuer))));
		jws.sign(new RSASSASigner(TestKeys.DEFAULT_PRIVATE_KEY));
		JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = JwtIssuerAuthenticationManagerResolver
			.fromTrustedIssuers(issuer);
		Authentication token = withBearerToken(jws.serialize());
		AuthenticationManager authenticationManager = authenticationManagerResolver.resolve(null);
		assertThat(authenticationManager).isNotNull();
		JwtDecoder decoder = mock(JwtDecoder.class);
		Jwt jwt = TestJwts.user();
		given(decoder.decode(token.getName())).willReturn(jwt);
		try (MockedStatic<JwtDecoders> jwtDecoders = mockStatic(JwtDecoders.class)) {
			given(JwtDecoders.fromIssuerLocation(issuer)).willReturn(decoder);
			Authentication authentication = authenticationManager.authenticate(token);
			assertThat(authentication.isAuthenticated()).isTrue();
		}
	}

	@Test
	public void resolveWhenUsingFromTrustedIssuersPredicateThenReturnsAuthenticationManager() throws Exception {
		String issuer = "https://idp.example";

		// @formatter:on
		JWSObject jws = new JWSObject(new JWSHeader(JWSAlgorithm.RS256),
				new Payload(new JSONObject(Collections.singletonMap(JwtClaimNames.ISS, issuer))));
		jws.sign(new RSASSASigner(TestKeys.DEFAULT_PRIVATE_KEY));
		JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = JwtIssuerAuthenticationManagerResolver
			.fromTrustedIssuers(issuer::equals);
		Authentication token = withBearerToken(jws.serialize());
		JwtDecoder decoder = mock(JwtDecoder.class);
		Jwt jwt = TestJwts.user();
		given(decoder.decode(token.getName())).willReturn(jwt);
		try (MockedStatic<JwtDecoders> jwtDecoders = mockStatic(JwtDecoders.class)) {
			given(JwtDecoders.fromIssuerLocation(issuer)).willReturn(decoder);
			AuthenticationManager authenticationManager = authenticationManagerResolver.resolve(null);
			assertThat(authenticationManager).isNotNull();
			Authentication authentication = authenticationManager.authenticate(token);
			assertThat(authentication.isAuthenticated()).isTrue();
		}
	}

	@Test
	public void resolveWhenUsingUntrustedIssuerThenException() {
		JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = JwtIssuerAuthenticationManagerResolver
			.fromTrustedIssuers("other", "issuers");
		Authentication token = withBearerToken(this.jwt);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(null).authenticate(token))
				.withMessageContaining("Invalid issuer");
		// @formatter:on
	}

	@Test
	public void resolveWhenUsingCustomIssuerAuthenticationManagerResolverThenUses() {
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerAuthenticationManagerResolver(
				(issuer) -> authenticationManager);
		Authentication token = withBearerToken(this.jwt);
		authenticationManagerResolver.resolve(null).authenticate(token);
		verify(authenticationManager).authenticate(token);
	}

	@Test
	public void resolveWhenUsingExternalSourceThenRespondsToChanges() {
		Authentication token = withBearerToken(this.jwt);
		Map<String, AuthenticationManager> authenticationManagers = new HashMap<>();
		JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerAuthenticationManagerResolver(
				authenticationManagers::get);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(null).authenticate(token))
				.withMessageContaining("Invalid issuer");
		// @formatter:on
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		authenticationManagers.put("trusted", authenticationManager);
		authenticationManagerResolver.resolve(null).authenticate(token);
		verify(authenticationManager).authenticate(token);
		authenticationManagers.clear();
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(null).authenticate(token))
				.withMessageContaining("Invalid issuer");
		// @formatter:on
	}

	@Test
	public void resolveWhenBearerTokenMalformedThenException() {
		JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = JwtIssuerAuthenticationManagerResolver
			.fromTrustedIssuers("trusted");
		Authentication token = withBearerToken("jwt");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(null).authenticate(token))
				.withMessageNotContaining("Invalid issuer");
		// @formatter:on
	}

	@Test
	public void resolveWhenBearerTokenNoIssuerThenException() {
		JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = JwtIssuerAuthenticationManagerResolver
			.fromTrustedIssuers("trusted");
		Authentication token = withBearerToken(this.noIssuer);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(null).authenticate(token))
				.withMessageContaining("Missing issuer");
		// @formatter:on
	}

	@Test
	public void resolveWhenBearerTokenEvilThenGenericException() {
		JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = JwtIssuerAuthenticationManagerResolver
			.fromTrustedIssuers("trusted");
		Authentication token = withBearerToken(this.evil);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver
						.resolve(null).authenticate(token)
				)
				.withMessage("Invalid issuer");
		// @formatter:on
	}

	@Test
	public void factoryWhenNullOrEmptyIssuersThenException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> JwtIssuerAuthenticationManagerResolver.fromTrustedIssuers((Predicate<String>) null));
		assertThatIllegalArgumentException()
			.isThrownBy(() -> JwtIssuerAuthenticationManagerResolver.fromTrustedIssuers((Collection<String>) null));
		assertThatIllegalArgumentException()
			.isThrownBy(() -> JwtIssuerAuthenticationManagerResolver.fromTrustedIssuers(Collections.emptyList()));
	}

	@Test
	public void constructorWhenNullAuthenticationManagerResolverThenException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new JwtIssuerAuthenticationManagerResolver((AuthenticationManagerResolver) null));
	}

	private Authentication withBearerToken(String token) {
		return new BearerTokenAuthenticationToken(token);
	}

	private String jwt(String claim, String value) {
		PlainJWT jwt = new PlainJWT(new JWTClaimsSet.Builder().claim(claim, value).build());
		return jwt.serialize();
	}

}
