/*
 * Copyright 2020-2024 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeActor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.util.TestX509Certificates;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link DefaultOAuth2TokenCustomizers}.
 *
 * @author Steve Riesenberg
 * @author Joe Grandja
 */
class DefaultOAuth2TokenCustomizersTests {

	private static final String ISSUER_1 = "issuer-1";

	private static final String ISSUER_2 = "issuer-2";

	private JwsHeader.Builder jwsHeaderBuilder;

	private JwtClaimsSet.Builder jwtClaimsBuilder;

	@BeforeEach
	void setUp() {
		this.jwsHeaderBuilder = JwsHeader.with(SignatureAlgorithm.RS256);
		this.jwtClaimsBuilder = JwtClaimsSet.builder().issuer(ISSUER_1);
	}

	@Test
	void customizeWhenTokenTypeIsRefreshTokenThenNoClaimsAdded() {
		// @formatter:off
		JwtEncodingContext tokenContext = JwtEncodingContext.with(this.jwsHeaderBuilder, this.jwtClaimsBuilder)
				.tokenType(OAuth2TokenType.REFRESH_TOKEN)
				.build();
		// @formatter:on
		DefaultOAuth2TokenCustomizers.jwtCustomizer().customize(tokenContext);
		JwtClaimsSet jwtClaimsSet = this.jwtClaimsBuilder.build();
		assertThat(jwtClaimsSet.getClaims()).containsOnly(entry(JwtClaimNames.ISS, ISSUER_1));
	}

	@Test
	void customizeWhenAuthorizationGrantIsNullThenNoClaimsAdded() {
		// @formatter:off
		JwtEncodingContext tokenContext = JwtEncodingContext.with(this.jwsHeaderBuilder, this.jwtClaimsBuilder)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.build();
		// @formatter:on
		DefaultOAuth2TokenCustomizers.jwtCustomizer().customize(tokenContext);
		JwtClaimsSet jwtClaimsSet = this.jwtClaimsBuilder.build();
		assertThat(jwtClaimsSet.getClaims()).containsOnly(entry(JwtClaimNames.ISS, ISSUER_1));
	}

	@Test
	void customizeWhenTokenExchangeGrantAndResourcesThenNoClaimsAdded() {
		OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication = mock(
				OAuth2TokenExchangeAuthenticationToken.class);
		given(tokenExchangeAuthentication.getResources()).willReturn(Set.of("resource1", "resource2"));
		// @formatter:off
		JwtEncodingContext tokenContext = JwtEncodingContext.with(this.jwsHeaderBuilder, this.jwtClaimsBuilder)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.authorizationGrant(tokenExchangeAuthentication)
				.build();
		// @formatter:on
		DefaultOAuth2TokenCustomizers.jwtCustomizer().customize(tokenContext);
		JwtClaimsSet jwtClaimsSet = this.jwtClaimsBuilder.build();
		// We do not populate claims (e.g. `aud`) based on the resource parameter
		assertThat(jwtClaimsSet.getClaims()).containsOnly(entry(JwtClaimNames.ISS, ISSUER_1));
	}

	@Test
	void customizeWhenTokenExchangeGrantAndAudiencesThenNoClaimsAdded() {
		OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication = mock(
				OAuth2TokenExchangeAuthenticationToken.class);
		given(tokenExchangeAuthentication.getAudiences()).willReturn(Set.of("audience1", "audience2"));
		// @formatter:off
		JwtEncodingContext tokenContext = JwtEncodingContext.with(this.jwsHeaderBuilder, this.jwtClaimsBuilder)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.authorizationGrant(tokenExchangeAuthentication)
				.build();
		// @formatter:on
		DefaultOAuth2TokenCustomizers.jwtCustomizer().customize(tokenContext);
		JwtClaimsSet jwtClaimsSet = this.jwtClaimsBuilder.build();
		// NOTE: We do not populate claims (e.g. `aud`) based on the audience parameter
		assertThat(jwtClaimsSet.getClaims()).containsOnly(entry(JwtClaimNames.ISS, ISSUER_1));
	}

	@Test
	void customizeWhenTokenExchangeGrantAndDelegationThenActClaimAdded() {
		OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication = mock(
				OAuth2TokenExchangeAuthenticationToken.class);
		given(tokenExchangeAuthentication.getAudiences()).willReturn(Collections.emptySet());

		Authentication subject = new TestingAuthenticationToken("subject", null);
		OAuth2TokenExchangeActor actor1 = new OAuth2TokenExchangeActor(
				Map.of(JwtClaimNames.ISS, ISSUER_1, JwtClaimNames.SUB, "actor1"));
		OAuth2TokenExchangeActor actor2 = new OAuth2TokenExchangeActor(
				Map.of(JwtClaimNames.ISS, ISSUER_2, JwtClaimNames.SUB, "actor2"));
		OAuth2TokenExchangeCompositeAuthenticationToken principal = new OAuth2TokenExchangeCompositeAuthenticationToken(
				subject, List.of(actor1, actor2));

		// @formatter:off
		JwtEncodingContext tokenContext = JwtEncodingContext.with(this.jwsHeaderBuilder, this.jwtClaimsBuilder)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.principal(principal)
				.authorizationGrant(tokenExchangeAuthentication)
				.build();
		// @formatter:on
		DefaultOAuth2TokenCustomizers.jwtCustomizer().customize(tokenContext);
		JwtClaimsSet jwtClaimsSet = this.jwtClaimsBuilder.build();
		assertThat(jwtClaimsSet.getClaims()).isNotEmpty();
		assertThat(jwtClaimsSet.getClaims()).hasSize(2);
		assertThat(jwtClaimsSet.getClaims().get("act")).isNotNull();
		@SuppressWarnings("unchecked")
		Map<String, Object> actClaim1 = (Map<String, Object>) jwtClaimsSet.getClaims().get("act");
		assertThat(actClaim1.get(JwtClaimNames.ISS)).isEqualTo(ISSUER_1);
		assertThat(actClaim1.get(JwtClaimNames.SUB)).isEqualTo("actor1");
		@SuppressWarnings("unchecked")
		Map<String, Object> actClaim2 = (Map<String, Object>) actClaim1.get("act");
		assertThat(actClaim2.get(JwtClaimNames.ISS)).isEqualTo(ISSUER_2);
		assertThat(actClaim2.get(JwtClaimNames.SUB)).isEqualTo("actor2");
	}

	@Test
	void customizeWhenPKIX509ClientCertificateAndCertificateBoundAccessTokensThenX5tClaimAdded() {
		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
				.clientSettings(
						ClientSettings.builder()
								.x509CertificateSubjectDN(TestX509Certificates.DEMO_CLIENT_PKI_CERTIFICATE[0].getSubjectX500Principal().getName())
								.build()
				)
				.tokenSettings(
						TokenSettings.builder()
								.x509CertificateBoundAccessTokens(true)
								.build()
				)
				.build();
		// @formatter:on
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.TLS_CLIENT_AUTH, TestX509Certificates.DEMO_CLIENT_PKI_CERTIFICATE);
		OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthentication = new OAuth2ClientCredentialsAuthenticationToken(
				clientPrincipal, null, null);
		// @formatter:off
		JwtEncodingContext tokenContext = JwtEncodingContext.with(this.jwsHeaderBuilder, this.jwtClaimsBuilder)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.registeredClient(registeredClient)
				.authorizationGrant(clientCredentialsAuthentication)
				.build();
		// @formatter:on
		DefaultOAuth2TokenCustomizers.jwtCustomizer().customize(tokenContext);
		JwtClaimsSet jwtClaimsSet = this.jwtClaimsBuilder.build();
		assertThat(jwtClaimsSet.getClaims()).isNotEmpty();
		assertThat(jwtClaimsSet.getClaims()).hasSize(2);
		Map<String, Object> cnfClaim = jwtClaimsSet.getClaim("cnf");
		assertThat(cnfClaim).isNotEmpty();
		assertThat(cnfClaim.get("x5t#S256")).isNotNull();
	}

	@Test
	void customizeWhenSelfSignedX509ClientCertificateAndCertificateBoundAccessTokensThenX5tClaimAdded() {
		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
				.clientSettings(
						ClientSettings.builder()
								.jwkSetUrl("https://client.example.com/jwks")
								.build()
				)
				.tokenSettings(
						TokenSettings.builder()
								.x509CertificateBoundAccessTokens(true)
								.build()
				)
				.build();
		// @formatter:on
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
				TestX509Certificates.DEMO_CLIENT_SELF_SIGNED_CERTIFICATE);
		OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthentication = new OAuth2ClientCredentialsAuthenticationToken(
				clientPrincipal, null, null);
		// @formatter:off
		JwtEncodingContext tokenContext = JwtEncodingContext.with(this.jwsHeaderBuilder, this.jwtClaimsBuilder)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.registeredClient(registeredClient)
				.authorizationGrant(clientCredentialsAuthentication)
				.build();
		// @formatter:on
		DefaultOAuth2TokenCustomizers.jwtCustomizer().customize(tokenContext);
		JwtClaimsSet jwtClaimsSet = this.jwtClaimsBuilder.build();
		assertThat(jwtClaimsSet.getClaims()).isNotEmpty();
		assertThat(jwtClaimsSet.getClaims()).hasSize(2);
		Map<String, Object> cnfClaim = jwtClaimsSet.getClaim("cnf");
		assertThat(cnfClaim).isNotEmpty();
		assertThat(cnfClaim.get("x5t#S256")).isNotNull();
	}

}
