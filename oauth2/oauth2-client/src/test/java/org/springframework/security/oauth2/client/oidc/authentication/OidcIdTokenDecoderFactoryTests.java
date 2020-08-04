/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.authentication;

import java.util.Map;
import java.util.function.Function;

import org.junit.Before;
import org.junit.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Joe Grandja
 * @author Rafael Dominguez
 * @since 5.2
 */
public class OidcIdTokenDecoderFactoryTests {

	private ClientRegistration.Builder registration = TestClientRegistrations.clientRegistration().scope("openid");

	private OidcIdTokenDecoderFactory idTokenDecoderFactory;

	@Before
	public void setUp() {
		this.idTokenDecoderFactory = new OidcIdTokenDecoderFactory();
	}

	@Test
	public void createDefaultClaimTypeConvertersWhenCalledThenDefaultsAreCorrect() {
		Map<String, Converter<Object, ?>> claimTypeConverters = OidcIdTokenDecoderFactory
				.createDefaultClaimTypeConverters();
		assertThat(claimTypeConverters).containsKey(IdTokenClaimNames.ISS);
		assertThat(claimTypeConverters).containsKey(IdTokenClaimNames.AUD);
		assertThat(claimTypeConverters).containsKey(IdTokenClaimNames.NONCE);
		assertThat(claimTypeConverters).containsKey(IdTokenClaimNames.EXP);
		assertThat(claimTypeConverters).containsKey(IdTokenClaimNames.IAT);
		assertThat(claimTypeConverters).containsKey(IdTokenClaimNames.AUTH_TIME);
		assertThat(claimTypeConverters).containsKey(IdTokenClaimNames.AMR);
		assertThat(claimTypeConverters).containsKey(StandardClaimNames.EMAIL_VERIFIED);
		assertThat(claimTypeConverters).containsKey(StandardClaimNames.PHONE_NUMBER_VERIFIED);
		assertThat(claimTypeConverters).containsKey(StandardClaimNames.UPDATED_AT);
	}

	@Test
	public void setJwtValidatorFactoryWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.idTokenDecoderFactory.setJwtValidatorFactory(null));
	}

	@Test
	public void setJwsAlgorithmResolverWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.idTokenDecoderFactory.setJwsAlgorithmResolver(null));
	}

	@Test
	public void setClaimTypeConverterFactoryWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.idTokenDecoderFactory.setClaimTypeConverterFactory(null));
	}

	@Test
	public void createDecoderWhenClientRegistrationNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.idTokenDecoderFactory.createDecoder(null));
	}

	@Test
	public void createDecoderWhenJwsAlgorithmDefaultAndJwkSetUriEmptyThenThrowOAuth2AuthenticationException() {
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.idTokenDecoderFactory.createDecoder(this.registration.jwkSetUri(null).build()))
				.withMessage("[missing_signature_verifier] Failed to find a Signature Verifier "
						+ "for Client Registration: 'registration-id'. "
						+ "Check to ensure you have configured the JwkSet URI.");
	}

	@Test
	public void createDecoderWhenJwsAlgorithmEcAndJwkSetUriEmptyThenThrowOAuth2AuthenticationException() {
		this.idTokenDecoderFactory.setJwsAlgorithmResolver((clientRegistration) -> SignatureAlgorithm.ES256);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.idTokenDecoderFactory.createDecoder(this.registration.jwkSetUri(null).build()))
				.withMessage("[missing_signature_verifier] Failed to find a Signature Verifier "
						+ "for Client Registration: 'registration-id'. "
						+ "Check to ensure you have configured the JwkSet URI.");
	}

	@Test
	public void createDecoderWhenJwsAlgorithmHmacAndClientSecretNullThenThrowOAuth2AuthenticationException() {
		this.idTokenDecoderFactory.setJwsAlgorithmResolver((clientRegistration) -> MacAlgorithm.HS256);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(
						() -> this.idTokenDecoderFactory.createDecoder(this.registration.clientSecret(null).build()))
				.withMessage("[missing_signature_verifier] Failed to find a Signature Verifier "
						+ "for Client Registration: 'registration-id'. "
						+ "Check to ensure you have configured the client secret.");
	}

	@Test
	public void createDecoderWhenJwsAlgorithmNullThenThrowOAuth2AuthenticationException() {
		this.idTokenDecoderFactory.setJwsAlgorithmResolver((clientRegistration) -> null);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.idTokenDecoderFactory.createDecoder(this.registration.build()))
				.withMessage("[missing_signature_verifier] Failed to find a Signature Verifier "
						+ "for Client Registration: 'registration-id'. "
						+ "Check to ensure you have configured a valid JWS Algorithm: 'null'");
	}

	@Test
	public void createDecoderWhenClientRegistrationValidThenReturnDecoder() {
		assertThat(this.idTokenDecoderFactory.createDecoder(this.registration.build())).isNotNull();
	}

	@Test
	public void createDecoderWhenCustomJwtValidatorFactorySetThenApplied() {
		Function<ClientRegistration, OAuth2TokenValidator<Jwt>> customJwtValidatorFactory = mock(Function.class);
		this.idTokenDecoderFactory.setJwtValidatorFactory(customJwtValidatorFactory);
		ClientRegistration clientRegistration = this.registration.build();
		given(customJwtValidatorFactory.apply(same(clientRegistration)))
				.willReturn(new OidcIdTokenValidator(clientRegistration));
		this.idTokenDecoderFactory.createDecoder(clientRegistration);
		verify(customJwtValidatorFactory).apply(same(clientRegistration));
	}

	@Test
	public void createDecoderWhenCustomJwsAlgorithmResolverSetThenApplied() {
		Function<ClientRegistration, JwsAlgorithm> customJwsAlgorithmResolver = mock(Function.class);
		this.idTokenDecoderFactory.setJwsAlgorithmResolver(customJwsAlgorithmResolver);
		ClientRegistration clientRegistration = this.registration.build();
		given(customJwsAlgorithmResolver.apply(same(clientRegistration))).willReturn(MacAlgorithm.HS256);
		this.idTokenDecoderFactory.createDecoder(clientRegistration);
		verify(customJwsAlgorithmResolver).apply(same(clientRegistration));
	}

	@Test
	public void createDecoderWhenCustomClaimTypeConverterFactorySetThenApplied() {
		Function<ClientRegistration, Converter<Map<String, Object>, Map<String, Object>>> customClaimTypeConverterFactory = mock(
				Function.class);
		this.idTokenDecoderFactory.setClaimTypeConverterFactory(customClaimTypeConverterFactory);
		ClientRegistration clientRegistration = this.registration.build();
		given(customClaimTypeConverterFactory.apply(same(clientRegistration)))
				.willReturn(new ClaimTypeConverter(OidcIdTokenDecoderFactory.createDefaultClaimTypeConverters()));
		this.idTokenDecoderFactory.createDecoder(clientRegistration);
		verify(customClaimTypeConverterFactory).apply(same(clientRegistration));
	}

}
