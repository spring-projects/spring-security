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

package org.springframework.security.oauth2.client.endpoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.UUID;
import java.util.function.Function;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.Before;
import org.junit.Test;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.MultiValueMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link NimbusJwtClientAuthenticationParametersConverter}.
 *
 * @author Joe Grandja
 */
public class NimbusJwtClientAuthenticationParametersConverterTests {

	private Function<ClientRegistration, JWK> jwkResolver;

	private NimbusJwtClientAuthenticationParametersConverter<OAuth2ClientCredentialsGrantRequest> converter;

	@Before
	public void setup() {
		this.jwkResolver = mock(Function.class);
		this.converter = new NimbusJwtClientAuthenticationParametersConverter<>(this.jwkResolver);
	}

	@Test
	public void constructorWhenJwkResolverNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new NimbusJwtClientAuthenticationParametersConverter<>(null))
				.withMessage("jwkResolver cannot be null");
	}

	@Test
	public void convertWhenAuthorizationGrantRequestNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.converter.convert(null))
				.withMessage("authorizationGrantRequest cannot be null");
	}

	@Test
	public void convertWhenOtherClientAuthenticationMethodThenNotCustomized() {
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials()
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.build();
		// @formatter:on
		OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest = new OAuth2ClientCredentialsGrantRequest(
				clientRegistration);
		assertThat(this.converter.convert(clientCredentialsGrantRequest)).isNull();
		verifyNoInteractions(this.jwkResolver);
	}

	@Test
	public void convertWhenJwkNotResolvedThenThrowOAuth2AuthorizationException() {
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials()
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
				.build();
		// @formatter:on
		OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest = new OAuth2ClientCredentialsGrantRequest(
				clientRegistration);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.converter.convert(clientCredentialsGrantRequest))
				.withMessage("[invalid_key] Failed to resolve JWK signing key for client registration '"
						+ clientRegistration.getRegistrationId() + "'.");
	}

	@Test
	public void convertWhenPrivateKeyJwtClientAuthenticationMethodThenCustomized() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkResolver.apply(any())).willReturn(rsaJwk);

		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials()
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
				.build();
		// @formatter:on

		OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest = new OAuth2ClientCredentialsGrantRequest(
				clientRegistration);
		MultiValueMap<String, String> parameters = this.converter.convert(clientCredentialsGrantRequest);

		assertThat(parameters.getFirst(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE))
				.isEqualTo("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
		String encodedJws = parameters.getFirst(OAuth2ParameterNames.CLIENT_ASSERTION);
		assertThat(encodedJws).isNotNull();

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaJwk.toRSAPublicKey()).build();
		Jwt jws = jwtDecoder.decode(encodedJws);

		assertThat(jws.getHeaders().get(JoseHeaderNames.ALG)).isEqualTo(SignatureAlgorithm.RS256.getName());
		assertThat(jws.getHeaders().get(JoseHeaderNames.KID)).isEqualTo(rsaJwk.getKeyID());
		assertThat(jws.<String>getClaim(JwtClaimNames.ISS)).isEqualTo(clientRegistration.getClientId());
		assertThat(jws.getSubject()).isEqualTo(clientRegistration.getClientId());
		assertThat(jws.getAudience())
				.isEqualTo(Collections.singletonList(clientRegistration.getProviderDetails().getTokenUri()));
		assertThat(jws.getId()).isNotNull();
		assertThat(jws.getIssuedAt()).isNotNull();
		assertThat(jws.getExpiresAt()).isNotNull();
	}

	@Test
	public void convertWhenClientSecretJwtClientAuthenticationMethodThenCustomized() {
		OctetSequenceKey secretJwk = TestJwks.DEFAULT_SECRET_JWK;
		given(this.jwkResolver.apply(any())).willReturn(secretJwk);

		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials()
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
				.build();
		// @formatter:on

		OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest = new OAuth2ClientCredentialsGrantRequest(
				clientRegistration);
		MultiValueMap<String, String> parameters = this.converter.convert(clientCredentialsGrantRequest);

		assertThat(parameters.getFirst(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE))
				.isEqualTo("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
		String encodedJws = parameters.getFirst(OAuth2ParameterNames.CLIENT_ASSERTION);
		assertThat(encodedJws).isNotNull();

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withSecretKey(secretJwk.toSecretKey()).build();
		Jwt jws = jwtDecoder.decode(encodedJws);

		assertThat(jws.getHeaders().get(JoseHeaderNames.ALG)).isEqualTo(MacAlgorithm.HS256.getName());
		assertThat(jws.getHeaders().get(JoseHeaderNames.KID)).isEqualTo(secretJwk.getKeyID());
		assertThat(jws.<String>getClaim(JwtClaimNames.ISS)).isEqualTo(clientRegistration.getClientId());
		assertThat(jws.getSubject()).isEqualTo(clientRegistration.getClientId());
		assertThat(jws.getAudience())
				.isEqualTo(Collections.singletonList(clientRegistration.getProviderDetails().getTokenUri()));
		assertThat(jws.getId()).isNotNull();
		assertThat(jws.getIssuedAt()).isNotNull();
		assertThat(jws.getExpiresAt()).isNotNull();
	}

	// gh-9814
	@Test
	public void convertWhenClientKeyChangesThenNewKeyUsed() throws Exception {
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials()
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
				.build();
		// @formatter:on

		RSAKey rsaJwk1 = TestJwks.DEFAULT_RSA_JWK;
		given(this.jwkResolver.apply(eq(clientRegistration))).willReturn(rsaJwk1);

		OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest = new OAuth2ClientCredentialsGrantRequest(
				clientRegistration);
		MultiValueMap<String, String> parameters = this.converter.convert(clientCredentialsGrantRequest);

		String encodedJws = parameters.getFirst(OAuth2ParameterNames.CLIENT_ASSERTION);
		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaJwk1.toRSAPublicKey()).build();
		jwtDecoder.decode(encodedJws);

		RSAKey rsaJwk2 = generateRsaJwk();
		given(this.jwkResolver.apply(eq(clientRegistration))).willReturn(rsaJwk2);

		parameters = this.converter.convert(clientCredentialsGrantRequest);

		encodedJws = parameters.getFirst(OAuth2ParameterNames.CLIENT_ASSERTION);
		jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaJwk2.toRSAPublicKey()).build();
		jwtDecoder.decode(encodedJws);
	}

	private static RSAKey generateRsaJwk() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		// @formatter:off
		return new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		// @formatter:on
	}

}
