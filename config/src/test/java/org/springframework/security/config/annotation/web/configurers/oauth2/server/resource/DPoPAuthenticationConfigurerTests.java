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

package org.springframework.security.config.annotation.web.configurers.oauth2.server.resource;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link DPoPAuthenticationConfigurer}.
 *
 * @author Joe Grandja
 */
@ExtendWith(SpringTestContextExtension.class)
public class DPoPAuthenticationConfigurerTests {

	private static final RSAPublicKey PROVIDER_RSA_PUBLIC_KEY = TestKeys.DEFAULT_PUBLIC_KEY;

	private static final RSAPrivateKey PROVIDER_RSA_PRIVATE_KEY = TestKeys.DEFAULT_PRIVATE_KEY;

	private static final ECPublicKey CLIENT_EC_PUBLIC_KEY = (ECPublicKey) TestKeys.DEFAULT_EC_KEY_PAIR.getPublic();

	private static final ECPrivateKey CLIENT_EC_PRIVATE_KEY = (ECPrivateKey) TestKeys.DEFAULT_EC_KEY_PAIR.getPrivate();

	private static NimbusJwtEncoder providerJwtEncoder;

	private static NimbusJwtEncoder clientJwtEncoder;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mvc;

	@BeforeAll
	public static void init() {
		RSAKey providerRsaKey = TestJwks.jwk(PROVIDER_RSA_PUBLIC_KEY, PROVIDER_RSA_PRIVATE_KEY).build();
		JWKSource<SecurityContext> providerJwkSource = (jwkSelector, securityContext) -> jwkSelector
			.select(new JWKSet(providerRsaKey));
		providerJwtEncoder = new NimbusJwtEncoder(providerJwkSource);
		ECKey clientEcKey = TestJwks.jwk(CLIENT_EC_PUBLIC_KEY, CLIENT_EC_PRIVATE_KEY).build();
		JWKSource<SecurityContext> clientJwkSource = (jwkSelector, securityContext) -> jwkSelector
			.select(new JWKSet(clientEcKey));
		clientJwtEncoder = new NimbusJwtEncoder(clientJwkSource);
	}

	@Test
	public void requestWhenDPoPAndBearerAuthenticationThenUnauthorized() throws Exception {
		this.spring.register(SecurityConfig.class, ResourceEndpoints.class).autowire();
		Set<String> scope = Collections.singleton("resource1.read");
		String accessToken = generateAccessToken(scope, CLIENT_EC_PUBLIC_KEY);
		String dPoPProof = generateDPoPProof(HttpMethod.GET.name(), "http://localhost/resource1", accessToken);
		// @formatter:off
		this.mvc.perform(get("/resource1")
						.header(HttpHeaders.AUTHORIZATION, "DPoP " + accessToken)
						.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
						.header("DPoP", dPoPProof))
				.andExpect(status().isUnauthorized());
		// @formatter:on
	}

	@Test
	public void requestWhenDPoPAccessTokenMalformedThenUnauthorized() throws Exception {
		this.spring.register(SecurityConfig.class, ResourceEndpoints.class).autowire();
		Set<String> scope = Collections.singleton("resource1.read");
		String accessToken = generateAccessToken(scope, CLIENT_EC_PUBLIC_KEY);
		String dPoPProof = generateDPoPProof(HttpMethod.GET.name(), "http://localhost/resource1", accessToken);
		// @formatter:off
		this.mvc.perform(get("/resource1")
						.header(HttpHeaders.AUTHORIZATION, "DPoP " + accessToken + " m a l f o r m e d ")
						.header("DPoP", dPoPProof))
				.andExpect(status().isUnauthorized());
		// @formatter:on
	}

	@Test
	public void requestWhenMultipleDPoPProofsThenUnauthorized() throws Exception {
		this.spring.register(SecurityConfig.class, ResourceEndpoints.class).autowire();
		Set<String> scope = Collections.singleton("resource1.read");
		String accessToken = generateAccessToken(scope, CLIENT_EC_PUBLIC_KEY);
		String dPoPProof = generateDPoPProof(HttpMethod.GET.name(), "http://localhost/resource1", accessToken);
		// @formatter:off
		this.mvc.perform(get("/resource1")
						.header(HttpHeaders.AUTHORIZATION, "DPoP " + accessToken)
						.header("DPoP", dPoPProof)
						.header("DPoP", dPoPProof))
				.andExpect(status().isUnauthorized());
		// @formatter:on
	}

	@Test
	public void requestWhenDPoPAuthenticationValidThenAccessed() throws Exception {
		this.spring.register(SecurityConfig.class, ResourceEndpoints.class).autowire();
		Set<String> scope = Collections.singleton("resource1.read");
		String accessToken = generateAccessToken(scope, CLIENT_EC_PUBLIC_KEY);
		String dPoPProof = generateDPoPProof(HttpMethod.GET.name(), "http://localhost/resource1", accessToken);
		// @formatter:off
		this.mvc.perform(get("/resource1")
						.header(HttpHeaders.AUTHORIZATION, "DPoP " + accessToken)
						.header("DPoP", dPoPProof))
				.andExpect(status().isOk())
				.andExpect(content().string("resource1"));
		// @formatter:on
	}

	private static String generateAccessToken(Set<String> scope, PublicKey clientPublicKey) {
		Map<String, Object> jktClaim = null;
		if (clientPublicKey != null) {
			try {
				String sha256Thumbprint = computeSHA256(clientPublicKey);
				jktClaim = new HashMap<>();
				jktClaim.put("jkt", sha256Thumbprint);
			}
			catch (Exception ignored) {
			}
		}
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(30, ChronoUnit.MINUTES);
		// @formatter:off
		JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
				.issuer("https://provider.com")
				.subject("subject")
				.issuedAt(issuedAt)
				.expiresAt(expiresAt)
				.id(UUID.randomUUID().toString())
				.claim(OAuth2ParameterNames.SCOPE, scope);
		if (jktClaim != null) {
			claimsBuilder.claim("cnf", jktClaim);	// Bind client public key
		}
		// @formatter:on
		Jwt jwt = providerJwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claimsBuilder.build()));
		return jwt.getTokenValue();
	}

	private static String generateDPoPProof(String method, String resourceUri, String accessToken) throws Exception {
		// @formatter:off
		Map<String, Object> publicJwk = TestJwks.jwk(CLIENT_EC_PUBLIC_KEY, CLIENT_EC_PRIVATE_KEY)
				.build()
				.toPublicJWK()
				.toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.ES256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", method)
				.claim("htu", resourceUri)
				.claim("ath", computeSHA256(accessToken))
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on
		Jwt jwt = clientJwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));
		return jwt.getTokenValue();
	}

	private static String computeSHA256(String value) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(value.getBytes(StandardCharsets.UTF_8));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

	private static String computeSHA256(PublicKey publicKey) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(publicKey.getEncoded());
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class SecurityConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) ->
					authorize
						.requestMatchers("/resource1").hasAnyAuthority("SCOPE_resource1.read", "SCOPE_resource1.write")
						.requestMatchers("/resource2").hasAnyAuthority("SCOPE_resource2.read", "SCOPE_resource2.write")
						.anyRequest().authenticated()
				)
				.oauth2ResourceServer((oauth2ResourceServer) ->
					oauth2ResourceServer
						.jwt(Customizer.withDefaults()));
			// @formatter:on
			return http.build();
		}

		@Bean
		NimbusJwtDecoder jwtDecoder() {
			return NimbusJwtDecoder.withPublicKey(PROVIDER_RSA_PUBLIC_KEY).build();
		}

	}

	@RestController
	static class ResourceEndpoints {

		@RequestMapping(value = "/resource1", method = { RequestMethod.GET, RequestMethod.POST })
		String resource1() {
			return "resource1";
		}

		@RequestMapping(value = "/resource2", method = { RequestMethod.GET, RequestMethod.POST })
		String resource2() {
			return "resource2";
		}

	}

}
