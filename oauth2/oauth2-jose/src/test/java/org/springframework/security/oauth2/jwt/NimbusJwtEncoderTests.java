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

package org.springframework.security.oauth2.jwt;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link NimbusJwtEncoder}.
 *
 * @author Joe Grandja
 */
public class NimbusJwtEncoderTests {

	private List<JWK> jwkList;

	private JWKSource<SecurityContext> jwkSource;

	private NimbusJwtEncoder jwtEncoder;

	@BeforeEach
	public void setUp() {
		this.jwkList = new ArrayList<>();
		this.jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(new JWKSet(this.jwkList));
		this.jwtEncoder = new NimbusJwtEncoder(this.jwkSource);
	}

	@Test
	public void constructorWhenJwkSourceNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new NimbusJwtEncoder(null))
			.withMessage("jwkSource cannot be null");
	}

	@Test
	public void encodeWhenParametersNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.jwtEncoder.encode(null))
			.withMessage("parameters cannot be null");
	}

	@Test
	public void encodeWhenClaimsNullThenThrowIllegalArgumentException() {
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();

		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, null)))
			.withMessage("claims cannot be null");
	}

	@Test
	public void encodeWhenJwkSelectFailedThenThrowJwtEncodingException() throws Exception {
		this.jwkSource = mock(JWKSource.class);
		this.jwtEncoder = new NimbusJwtEncoder(this.jwkSource);
		given(this.jwkSource.get(any(), any())).willThrow(new KeySourceException("key source error"));

		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		assertThatExceptionOfType(JwtEncodingException.class)
			.isThrownBy(() -> this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet)))
			.withMessageContaining("Failed to select a JWK signing key -> key source error");
	}

	@Test
	public void encodeWhenJwkMultipleSelectedThenThrowJwtEncodingException() throws Exception {
		RSAKey rsaJwk = TestJwks.rsa().algorithm(JWSAlgorithm.RS256).build();
		this.jwkList.add(rsaJwk);
		this.jwkList.add(rsaJwk);

		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		assertThatExceptionOfType(JwtEncodingException.class)
			.isThrownBy(() -> this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet)))
			.withMessageContaining("Failed to select a key since there are multiple for the signing algorithm [RS256]");
	}

	@Test
	public void encodeWhenJwkSelectEmptyThenThrowJwtEncodingException() {
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		assertThatExceptionOfType(JwtEncodingException.class)
			.isThrownBy(() -> this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet)))
			.withMessageContaining("Failed to select a JWK signing key");
	}

	@Test
	public void encodeWhenHeadersNotProvidedThenDefaulted() {
		// @formatter:off
		RSAKey rsaJwk = TestJwks.jwk(TestKeys.DEFAULT_PUBLIC_KEY, TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("rsa-jwk-1")
				.build();
		this.jwkList.add(rsaJwk);
		// @formatter:on

		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		Jwt encodedJws = this.jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet));

		assertThat(encodedJws.getHeaders()).containsEntry(JoseHeaderNames.ALG, SignatureAlgorithm.RS256);
	}

	@Test
	public void encodeWhenJwkSelectWithProvidedKidThenSelected() {
		// @formatter:off
		RSAKey rsaJwk1 = TestJwks.jwk(TestKeys.DEFAULT_PUBLIC_KEY, TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("rsa-jwk-1")
				.build();
		this.jwkList.add(rsaJwk1);
		RSAKey rsaJwk2 = TestJwks.jwk(TestKeys.DEFAULT_PUBLIC_KEY, TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("rsa-jwk-2")
				.build();
		this.jwkList.add(rsaJwk2);
		// @formatter:on

		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).keyId(rsaJwk2.getKeyID()).build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		Jwt encodedJws = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet));

		assertThat(encodedJws.getHeaders()).containsEntry(JoseHeaderNames.KID, rsaJwk2.getKeyID());
	}

	@Test
	public void encodeWhenJwkSelectWithProvidedX5TS256ThenSelected() {
		// @formatter:off
		RSAKey rsaJwk1 = TestJwks.jwk(TestKeys.DEFAULT_PUBLIC_KEY, TestKeys.DEFAULT_PRIVATE_KEY)
				.x509CertSHA256Thumbprint(new Base64URL("x509CertSHA256Thumbprint-1"))
				.keyID(null)
				.build();
		this.jwkList.add(rsaJwk1);
		RSAKey rsaJwk2 = TestJwks.jwk(TestKeys.DEFAULT_PUBLIC_KEY, TestKeys.DEFAULT_PRIVATE_KEY)
				.x509CertSHA256Thumbprint(new Base64URL("x509CertSHA256Thumbprint-2"))
				.keyID(null)
				.build();
		this.jwkList.add(rsaJwk2);
		// @formatter:on

		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
			.x509SHA256Thumbprint(rsaJwk1.getX509CertSHA256Thumbprint().toString())
			.build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		Jwt encodedJws = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet));

		assertThat(encodedJws.getHeaders()).containsEntry(JoseHeaderNames.X5T_S256,
				rsaJwk1.getX509CertSHA256Thumbprint().toString());
		assertThat(encodedJws.getHeaders().get(JoseHeaderNames.KID)).isNull();
	}

	@Test
	public void encodeWhenJwkUseEncryptionThenThrowJwtEncodingException() throws Exception {
		// @formatter:off
		RSAKey rsaJwk = TestJwks.jwk(TestKeys.DEFAULT_PUBLIC_KEY, TestKeys.DEFAULT_PRIVATE_KEY)
				.keyUse(KeyUse.ENCRYPTION)
				.build();
		// @formatter:on

		this.jwkSource = mock(JWKSource.class);
		this.jwtEncoder = new NimbusJwtEncoder(this.jwkSource);
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		assertThatExceptionOfType(JwtEncodingException.class)
			.isThrownBy(() -> this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet)))
			.withMessageContaining(
					"Failed to create a JWS Signer -> The JWK use must be sig (signature) or unspecified");
	}

	@Test
	public void encodeWhenSuccessThenDecodes() throws Exception {
		// @formatter:off
		RSAKey rsaJwk = TestJwks.jwk(TestKeys.DEFAULT_PUBLIC_KEY, TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("rsa-jwk-1")
				.x509CertSHA256Thumbprint(new Base64URL("x509CertSHA256Thumbprint-1"))
				.build();
		this.jwkList.add(rsaJwk);
		// @formatter:on

		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		Jwt encodedJws = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet));

		assertThat(encodedJws.getHeaders()).containsEntry(JoseHeaderNames.ALG, jwsHeader.getAlgorithm());
		assertThat(encodedJws.getHeaders().get(JoseHeaderNames.JKU)).isNull();
		assertThat(encodedJws.getHeaders().get(JoseHeaderNames.JWK)).isNull();
		assertThat(encodedJws.getHeaders()).containsEntry(JoseHeaderNames.KID, rsaJwk.getKeyID());
		assertThat(encodedJws.getHeaders().get(JoseHeaderNames.X5U)).isNull();
		assertThat(encodedJws.getHeaders().get(JoseHeaderNames.X5C)).isNull();
		assertThat(encodedJws.getHeaders().get(JoseHeaderNames.X5T)).isNull();
		assertThat(encodedJws.getHeaders()).containsEntry(JoseHeaderNames.X5T_S256,
				rsaJwk.getX509CertSHA256Thumbprint().toString());
		assertThat(encodedJws.getHeaders().get(JoseHeaderNames.TYP)).isNull();
		assertThat(encodedJws.getHeaders().get(JoseHeaderNames.CTY)).isNull();
		assertThat(encodedJws.getHeaders().get(JoseHeaderNames.CRIT)).isNull();

		assertThat(encodedJws.getIssuer()).isEqualTo(jwtClaimsSet.getIssuer());
		assertThat(encodedJws.getSubject()).isEqualTo(jwtClaimsSet.getSubject());
		assertThat(encodedJws.getAudience()).isEqualTo(jwtClaimsSet.getAudience());
		assertThat(encodedJws.getExpiresAt()).isEqualTo(jwtClaimsSet.getExpiresAt());
		assertThat(encodedJws.getNotBefore()).isEqualTo(jwtClaimsSet.getNotBefore());
		assertThat(encodedJws.getIssuedAt()).isEqualTo(jwtClaimsSet.getIssuedAt());
		assertThat(encodedJws.getId()).isEqualTo(jwtClaimsSet.getId());
		assertThat(encodedJws.<String>getClaim("custom-claim-name")).isEqualTo("custom-claim-value");

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaJwk.toRSAPublicKey()).build();
		jwtDecoder.decode(encodedJws.getTokenValue());
	}

	@Test
	public void encodeWhenKeysRotatedThenNewKeyUsed() throws Exception {
		TestJWKSource jwkSource = new TestJWKSource();
		JWKSource<SecurityContext> jwkSourceDelegate = spy(new JWKSource<SecurityContext>() {
			@Override
			public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) {
				return jwkSource.get(jwkSelector, context);
			}
		});
		NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSourceDelegate);

		JwkListResultCaptor jwkListResultCaptor = new JwkListResultCaptor();
		willAnswer(jwkListResultCaptor).given(jwkSourceDelegate).get(any(), any());

		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		Jwt encodedJws = jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet));

		JWK jwk1 = jwkListResultCaptor.getResult().get(0);
		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(((RSAKey) jwk1).toRSAPublicKey()).build();
		jwtDecoder.decode(encodedJws.getTokenValue());

		jwkSource.rotate(); // Simulate key rotation

		encodedJws = jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet));

		JWK jwk2 = jwkListResultCaptor.getResult().get(0);
		jwtDecoder = NimbusJwtDecoder.withPublicKey(((RSAKey) jwk2).toRSAPublicKey()).build();
		jwtDecoder.decode(encodedJws.getTokenValue());

		assertThat(jwk1.getKeyID()).isNotEqualTo(jwk2.getKeyID());
	}

	@Test
	public void encodeWhenMultipleKeysThenJwkSelectorUsed() throws Exception {
		JWK jwk = TestJwks.rsa().algorithm(JWSAlgorithm.RS256).build();
		JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);
		given(jwkSource.get(any(), any())).willReturn(List.of(jwk, jwk));
		Converter<List<JWK>, JWK> selector = mock(Converter.class);
		given(selector.convert(any())).willReturn(TestJwks.DEFAULT_RSA_JWK);

		NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
		jwtEncoder.setJwkSelector(selector);

		JwtClaimsSet claims = JwtClaimsSet.builder().subject("sub").build();
		jwtEncoder.encode(JwtEncoderParameters.from(claims));

		verify(selector).convert(any());
	}

	@Test
	public void encodeWhenSingleKeyThenJwkSelectorIsNotUsed() throws Exception {
		JWK jwk = TestJwks.rsa().algorithm(JWSAlgorithm.RS256).build();
		JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);
		given(jwkSource.get(any(), any())).willReturn(List.of(jwk));
		Converter<List<JWK>, JWK> selector = mock(Converter.class);

		NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
		jwtEncoder.setJwkSelector(selector);

		JwtClaimsSet claims = JwtClaimsSet.builder().subject("sub").build();
		jwtEncoder.encode(JwtEncoderParameters.from(claims));

		verifyNoInteractions(selector);
	}

	@Test
	public void encodeWhenNoKeysThenJwkSelectorIsNotUsed() throws Exception {
		JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);
		given(jwkSource.get(any(), any())).willReturn(List.of());
		Converter<List<JWK>, JWK> selector = mock(Converter.class);

		NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
		jwtEncoder.setJwkSelector(selector);

		JwtClaimsSet claims = JwtClaimsSet.builder().subject("sub").build();
		assertThatExceptionOfType(JwtEncodingException.class)
			.isThrownBy(() -> jwtEncoder.encode(JwtEncoderParameters.from(claims)));

		verifyNoInteractions(selector);
	}

	private static final class JwkListResultCaptor implements Answer<List<JWK>> {

		private List<JWK> result;

		private List<JWK> getResult() {
			return this.result;
		}

		@SuppressWarnings("unchecked")
		@Override
		public List<JWK> answer(InvocationOnMock invocationOnMock) throws Throwable {
			this.result = (List<JWK>) invocationOnMock.callRealMethod();
			return this.result;
		}

	}

	private static final class TestJWKSource implements JWKSource<SecurityContext> {

		private int keyId = 1000;

		private JWKSet jwkSet;

		private TestJWKSource() {
			init();
		}

		@Override
		public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) {
			return jwkSelector.select(this.jwkSet);
		}

		private void init() {
			// @formatter:off
			RSAKey rsaJwk = TestJwks.jwk(TestKeys.DEFAULT_PUBLIC_KEY, TestKeys.DEFAULT_PRIVATE_KEY)
					.keyID("rsa-jwk-" + this.keyId++)
					.build();
			ECKey ecJwk = TestJwks.jwk((ECPublicKey) TestKeys.DEFAULT_EC_KEY_PAIR.getPublic(), (ECPrivateKey) TestKeys.DEFAULT_EC_KEY_PAIR.getPrivate())
					.keyID("ec-jwk-" + this.keyId++)
					.build();
			OctetSequenceKey secretJwk = TestJwks.jwk(TestKeys.DEFAULT_SECRET_KEY)
					.keyID("secret-jwk-" + this.keyId++)
					.build();
			// @formatter:on
			this.jwkSet = new JWKSet(Arrays.asList(rsaJwk, ecJwk, secretJwk));
		}

		private void rotate() {
			init();
		}

	}

}
