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

import org.springframework.core.convert.converter.Converter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoders;

import javax.servlet.http.HttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link JwtIssuerAuthenticationManagerResolver}
 */
public class JwtIssuerAuthenticationManagerResolverTests {

	private static final String DEFAULT_RESPONSE_TEMPLATE = "{\n" + "    \"issuer\": \"%s\", \n"
			+ "    \"jwks_uri\": \"%s/.well-known/jwks.json\" \n" + "}";

	private String jwt = jwt("iss", "trusted");

	private String evil = jwt("iss", "\"");

	private String noIssuer = jwt("sub", "sub");

	@Test
	public void resolveWhenUsingTrustedIssuerThenReturnsAuthenticationManager() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.start();
			String issuer = server.url("").toString();
			// @formatter:off
			server.enqueue(new MockResponse().setResponseCode(200)
					.setHeader("Content-Type", "application/json")
					.setBody(String.format(DEFAULT_RESPONSE_TEMPLATE, issuer, issuer)
			));
			// @formatter:on
			JWSObject jws = new JWSObject(new JWSHeader(JWSAlgorithm.RS256),
					new Payload(new JSONObject(Collections.singletonMap(JwtClaimNames.ISS, issuer))));
			jws.sign(new RSASSASigner(TestKeys.DEFAULT_PRIVATE_KEY));
			JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerAuthenticationManagerResolver(
					issuer);
			MockHttpServletRequest request = new MockHttpServletRequest();
			request.addHeader("Authorization", "Bearer " + jws.serialize());
			AuthenticationManager authenticationManager = authenticationManagerResolver.resolve(request);
			assertThat(authenticationManager).isNotNull();
			AuthenticationManager cachedAuthenticationManager = authenticationManagerResolver.resolve(request);
			assertThat(authenticationManager).isSameAs(cachedAuthenticationManager);
		}
	}

	@Test
	public void resolveWhenUsingTrustedIssuerAndCustomJwtAuthConverterThenReturnsAuthenticationManager() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.start();
			String issuer = server.url("").toString();
			// @formatter:off
			server.enqueue(new MockResponse().setResponseCode(200)
											 .setHeader("Content-Type", "application/json")
											 .setBody(String.format(DEFAULT_RESPONSE_TEMPLATE, issuer, issuer)
											 ));
			// @formatter:on
			JWSObject jws = new JWSObject(new JWSHeader(JWSAlgorithm.RS256),
										  new Payload(new JSONObject(Collections.singletonMap(JwtClaimNames.ISS, issuer))));
			jws.sign(new RSASSASigner(TestKeys.DEFAULT_PRIVATE_KEY));
			JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerAuthenticationManagerResolver(
					Collections.singletonList(issuer), new JwtAuthenticationConverter());
			MockHttpServletRequest request = new MockHttpServletRequest();
			request.addHeader("Authorization", "Bearer " + jws.serialize());
			AuthenticationManager authenticationManager = authenticationManagerResolver.resolve(request);
			assertThat(authenticationManager).isNotNull();
			AuthenticationManager cachedAuthenticationManager = authenticationManagerResolver.resolve(request);
			assertThat(authenticationManager).isSameAs(cachedAuthenticationManager);
		}
	}

	@Test
	public void resolveWhenUsingUntrustedIssuerThenException() {
		JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerAuthenticationManagerResolver(
				"other", "issuers");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Bearer " + this.jwt);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(request))
				.withMessageContaining("Invalid issuer");
		// @formatter:on
	}

	@Test
	public void resolveWhenUsingCustomIssuerAuthenticationManagerResolverThenUses() {
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerAuthenticationManagerResolver(
				(issuer) -> authenticationManager);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Bearer " + this.jwt);
		assertThat(authenticationManagerResolver.resolve(request)).isSameAs(authenticationManager);
	}

	@Test
	public void resolveWhenUsingCustomIssuerAuthenticationManagerResolverAndCustomIssuerConverterThenUses() {
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		Converter<HttpServletRequest, String> jwtAuthConverter = (Converter<HttpServletRequest, String>) mock(Converter.class);
		JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerAuthenticationManagerResolver(
				(issuer) -> authenticationManager, jwtAuthConverter);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Bearer " + this.jwt);
		assertThat(authenticationManagerResolver.resolve(request)).isSameAs(authenticationManager);
	}

	@Test
	public void resolveWhenUsingExternalSourceThenRespondsToChanges() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Bearer " + this.jwt);
		Map<String, AuthenticationManager> authenticationManagers = new HashMap<>();
		JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerAuthenticationManagerResolver(
				authenticationManagers::get);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(request))
				.withMessageContaining("Invalid issuer");
		// @formatter:on
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		authenticationManagers.put("trusted", authenticationManager);
		assertThat(authenticationManagerResolver.resolve(request)).isSameAs(authenticationManager);
		authenticationManagers.clear();
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(request))
				.withMessageContaining("Invalid issuer");
		// @formatter:on
	}

	@Test
	public void resolveWhenBearerTokenMalformedThenException() {
		JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerAuthenticationManagerResolver(
				"trusted");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Bearer jwt");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(request))
				.withMessageNotContaining("Invalid issuer");
		// @formatter:on
	}

	@Test
	public void resolveWhenBearerTokenNoIssuerThenException() {
		JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerAuthenticationManagerResolver(
				"trusted");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Bearer " + this.noIssuer);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver.resolve(request))
				.withMessageContaining("Missing issuer");
		// @formatter:on
	}

	@Test
	public void resolveWhenBearerTokenEvilThenGenericException() {
		JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerAuthenticationManagerResolver(
				"trusted");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Bearer " + this.evil);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> authenticationManagerResolver
						.resolve(request)
				)
				.withMessage("Invalid issuer");
		// @formatter:on
	}

	@Test
	public void constructorWhenNullOrEmptyIssuersThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JwtIssuerAuthenticationManagerResolver((Collection) null));
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JwtIssuerAuthenticationManagerResolver(Collections.emptyList()));
	}

	@Test
	public void constructorWhenNullAuthenticationManagerResolverThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JwtIssuerAuthenticationManagerResolver((AuthenticationManagerResolver) null));
	}

	@Test
	public void constructWhenNullIssuerConverterThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JwtIssuerAuthenticationManagerResolver(
						context -> new JwtAuthenticationProvider(
								JwtDecoders.fromIssuerLocation("trusted"))::authenticate, null)
				);
	}

	private String jwt(String claim, String value) {
		PlainJWT jwt = new PlainJWT(new JWTClaimsSet.Builder().claim(claim, value).build());
		return jwt.serialize();
	}

}
