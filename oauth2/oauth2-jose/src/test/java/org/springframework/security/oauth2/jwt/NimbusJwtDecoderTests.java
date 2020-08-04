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

package org.springframework.security.oauth2.jwt;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import javax.crypto.SecretKey;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import okhttp3.mockwebserver.MockWebServer;
import org.assertj.core.api.Assertions;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link NimbusJwtDecoder}
 *
 * @author Josh Cummings
 * @author Joe Grandja
 * @author Mykyta Bezverkhyi
 */
public class NimbusJwtDecoderTests {

	private static final String JWK_SET = "{\"keys\":[{\"p\":\"49neceJFs8R6n7WamRGy45F5Tv0YM-R2ODK3eSBUSLOSH2tAqjEVKOkLE5fiNA3ygqq15NcKRadB2pTVf-Yb5ZIBuKzko8bzYIkIqYhSh_FAdEEr0vHF5fq_yWSvc6swsOJGqvBEtuqtJY027u-G2gAQasCQdhyejer68zsTn8M\",\"kty\":\"RSA\",\"q\":\"tWR-ysspjZ73B6p2vVRVyHwP3KQWL5KEQcdgcmMOE_P_cPs98vZJfLhxobXVmvzuEWBpRSiqiuyKlQnpstKt94Cy77iO8m8ISfF3C9VyLWXi9HUGAJb99irWABFl3sNDff5K2ODQ8CmuXLYM25OwN3ikbrhEJozlXg_NJFSGD4E\",\"d\":\"FkZHYZlw5KSoqQ1i2RA2kCUygSUOf1OqMt3uomtXuUmqKBm_bY7PCOhmwbvbn4xZYEeHuTR8Xix-0KpHe3NKyWrtRjkq1T_un49_1LLVUhJ0dL-9_x0xRquVjhl_XrsRXaGMEHs8G9pLTvXQ1uST585gxIfmCe0sxPZLvwoic-bXf64UZ9BGRV3lFexWJQqCZp2S21HfoU7wiz6kfLRNi-K4xiVNB1gswm_8o5lRuY7zB9bRARQ3TS2G4eW7p5sxT3CgsGiQD3_wPugU8iDplqAjgJ5ofNJXZezoj0t6JMB_qOpbrmAM1EnomIPebSLW7Ky9SugEd6KMdL5lW6AuAQ\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"one\",\"qi\":\"wdkFu_tV2V1l_PWUUimG516Zvhqk2SWDw1F7uNDD-Lvrv_WNRIJVzuffZ8WYiPy8VvYQPJUrT2EXL8P0ocqwlaSTuXctrORcbjwgxDQDLsiZE0C23HYzgi0cofbScsJdhcBg7d07LAf7cdJWG0YVl1FkMCsxUlZ2wTwHfKWf-v4\",\"dp\":\"uwnPxqC-IxG4r33-SIT02kZC1IqC4aY7PWq0nePiDEQMQWpjjNH50rlq9EyLzbtdRdIouo-jyQXB01K15-XXJJ60dwrGLYNVqfsTd0eGqD1scYJGHUWG9IDgCsxyEnuG3s0AwbW2UolWVSsU2xMZGb9PurIUZECeD1XDZwMp2s0\",\"dq\":\"hra786AunB8TF35h8PpROzPoE9VJJMuLrc6Esm8eZXMwopf0yhxfN2FEAvUoTpLJu93-UH6DKenCgi16gnQ0_zt1qNNIVoRfg4rw_rjmsxCYHTVL3-RDeC8X_7TsEySxW0EgFTHh-nr6I6CQrAJjPM88T35KHtdFATZ7BCBB8AE\",\"n\":\"oXJ8OyOv_eRnce4akdanR4KYRfnC2zLV4uYNQpcFn6oHL0dj7D6kxQmsXoYgJV8ZVDn71KGmuLvolxsDncc2UrhyMBY6DVQVgMSVYaPCTgW76iYEKGgzTEw5IBRQL9w3SRJWd3VJTZZQjkXef48Ocz06PGF3lhbz4t5UEZtdF4rIe7u-977QwHuh7yRPBQ3sII-cVoOUMgaXB9SHcGF2iZCtPzL_IffDUcfhLQteGebhW8A6eUHgpD5A1PQ-JCw_G7UOzZAjjDjtNM2eqm8j-Ms_gqnm4MiCZ4E-9pDN77CAAPVN7kuX6ejs9KBXpk01z48i9fORYk9u7rAkh1HuQw\"}]}";

	private static final String MALFORMED_JWK_SET = "malformed";

	private static final String SIGNED_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJzY3AiOlsibWVzc2FnZTpyZWFkIl0sImV4cCI6NDY4Mzg5Nzc3Nn0.LtMVtIiRIwSyc3aX35Zl0JVwLTcQZAB3dyBOMHNaHCKUljwMrf20a_gT79LfhjDzE_fUVUmFiAO32W1vFnYpZSVaMDUgeIOIOpxfoe9shj_uYenAwIS-_UxqGVIJiJoXNZh_MK80ShNpvsQwamxWEEOAMBtpWNiVYNDMdfgho9n3o5_Z7Gjy8RLBo1tbDREbO9kTFwGIxm_EYpezmRCRq4w1DdS6UDW321hkwMxPnCMSWOvp-hRpmgY2yjzLgPJ6Aucmg9TJ8jloAP1DjJoF1gRR7NTAk8LOGkSjTzVYDYMbCF51YdpojhItSk80YzXiEsv1mTz4oMM49jXBmfXFMA";

	private static final String MALFORMED_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJuYmYiOnt9LCJleHAiOjQ2ODQyMjUwODd9.guoQvujdWvd3xw7FYQEn4D6-gzM_WqFvXdmvAUNSLbxG7fv2_LLCNujPdrBHJoYPbOwS1BGNxIKQWS1tylvqzmr1RohQ-RZ2iAM1HYQzboUlkoMkcd8ENM__ELqho8aNYBfqwkNdUOyBFoy7Syu_w2SoJADw2RTjnesKO6CVVa05bW118pDS4xWxqC4s7fnBjmZoTn4uQ-Kt9YSQZQk8YQxkJSiyanozzgyfgXULA6mPu1pTNU3FVFaK1i1av_xtH_zAPgb647ZeaNe4nahgqC5h8nhOlm8W2dndXbwAt29nd2ZWBsru_QwZz83XSKLhTPFz-mPBByZZDsyBbIHf9A";

	private static final String UNSIGNED_JWT = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOi0yMDMzMjI0OTcsImp0aSI6IjEyMyIsInR5cCI6IkpXVCJ9.";

	private static final String EMPTY_EXP_CLAIM_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJhdWRpZW5jZSJ9.D1eT0jpBEpuh74p-YT-uF81Z7rkVqIpUtJ5hWWFiVShZ9s8NIntK4Q1GlvlziiySSaVYaXtpTmDB3c8r-Z5Mj4ibihiueCSq7jaPD3sA8IMQKL-L6Uol8MSD_lSFE2n3fVBTxFeaejBKfZsDxnhzgpy8g7PncR47w8NHs-7tKO4qw7G_SV3hkNpDNoqZTfMImxyWEebgKM2pJAhN4das2CO1KAjYMfEByLcgYncE8fzdYPJhMFo2XRRSQABoeUBuKSAwIntBaOGvcb-qII_Hefc5U0cmpNItG75F2XfX803plKI4FFpAxJsbPKWSQmhs6bZOrhx0x74pY5LS3ghmJw";

	private static final String JWK_SET_URI = "https://issuer/.well-known/jwks.json";

	private static final String RS512_SIGNED_JWT = "eyJhbGciOiJSUzUxMiJ9.eyJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJleHAiOjE5NzQzMjYxMTl9.LKAx-60EBfD7jC1jb1eKcjO4uLvf3ssISV-8tN-qp7gAjSvKvj4YA9-V2mIb6jcS1X_xGmNy6EIimZXpWaBR3nJmeu-jpe85u4WaW2Ztr8ecAi-dTO7ZozwdtljKuBKKvj4u1nF70zyCNl15AozSG0W1ASrjUuWrJtfyDG6WoZ8VfNMuhtU-xUYUFvscmeZKUYQcJ1KS-oV5tHeF8aNiwQoiPC_9KXCOZtNEJFdq6-uzFdHxvOP2yex5Gbmg5hXonauIFXG2ZPPGdXzm-5xkhBpgM8U7A_6wb3So8wBvLYYm2245QUump63AJRAy8tQpwt4n9MvQxQgS3z9R-NK92A";

	private static final String RS256_SIGNED_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJleHAiOjE5NzQzMjYzMzl9.CT-H2OWEqmSs1NWmnta5ealLFvM8OlbQTjGhfRcKLNxrTrzsOkqBJl-AN3k16BQU7mS32o744TiiZ29NcDlxPsr1MqTlN86-dobPiuNIDLp3A1bOVdXMcVFuMYkrNv0yW0tGS9OjEqsCCuZDkZ1by6AhsHLbGwRY-6AQdcRouZygGpOQu1hNun5j8q5DpSTY4AXKARIFlF-O3OpVbPJ0ebr3Ki-i3U9p_55H0e4-wx2bqcApWlqgofl1I8NKWacbhZgn81iibup2W7E0CzCzh71u1Mcy3xk1sYePx-dwcxJnHmxJReBBWjJZEAeCrkbnn_OCuo2fA-EQyNJtlN5F2w";

	private static final String VERIFY_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq4yKxb6SNePdDmQi9xFCrP6QvHosErQzryknQTTTffs0t3cy3Er3lIceuhZ7yQNSCDfPFqG8GoyoKhuChRiA5D+J2ab7bqTa1QJKfnCyERoscftgN2fXPHjHoiKbpGV2tMVw8mXl//tePOAiKbMJaBUnlAvJgkk1rVm08dSwpLC1sr2M19euf9jwnRGkMRZuhp9iCPgECRke5T8Ixpv0uQjSmGHnWUKTFlbj8sM83suROR1Ue64JSGScANc5vk3huJ/J97qTC+K2oKj6L8d9O8dpc4obijEOJwpydNvTYDgbiivYeSB00KS9jlBkQ5B2QqLvLVEygDl3dp59nGx6YQIDAQAB";

	private static final MediaType APPLICATION_JWK_SET_JSON = new MediaType("application", "jwk-set+json");

	private static KeyFactory kf;

	NimbusJwtDecoder jwtDecoder = new NimbusJwtDecoder(withoutSigning());

	@BeforeClass
	public static void keyFactory() throws NoSuchAlgorithmException {
		kf = KeyFactory.getInstance("RSA");
	}

	@Test
	public void constructorWhenJwtProcessorIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new NimbusJwtDecoder(null));
	}

	@Test
	public void setClaimSetConverterWhenIsNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.jwtDecoder.setClaimSetConverter(null));
	}

	@Test
	public void setJwtValidatorWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.jwtDecoder.setJwtValidator(null));
	}

	@Test
	public void decodeWhenJwtInvalidThenThrowJwtException() {
		assertThatExceptionOfType(JwtException.class).isThrownBy(() -> this.jwtDecoder.decode("invalid"));
	}

	// gh-5168
	@Test
	public void decodeWhenExpClaimNullThenDoesNotThrowException() {
		this.jwtDecoder.decode(EMPTY_EXP_CLAIM_JWT);
	}

	@Test
	public void decodeWhenIatClaimNullThenDoesNotThrowException() {
		this.jwtDecoder.decode(SIGNED_JWT);
	}

	// gh-5457
	@Test
	public void decodeWhenPlainJwtThenExceptionDoesNotMentionClass() {
		assertThatExceptionOfType(BadJwtException.class).isThrownBy(() -> this.jwtDecoder.decode(UNSIGNED_JWT))
				.withMessageContaining("Unsupported algorithm of none");
	}

	@Test
	public void decodeWhenJwtIsMalformedThenReturnsStockException() {
		assertThatExceptionOfType(BadJwtException.class).isThrownBy(() -> this.jwtDecoder.decode(MALFORMED_JWT))
				.withMessage("An error occurred while attempting to decode the Jwt: Malformed payload");
	}

	@Test
	public void decodeWhenJwtFailsValidationThenReturnsCorrespondingErrorMessage() {
		OAuth2Error failure = new OAuth2Error("mock-error", "mock-description", "mock-uri");
		OAuth2TokenValidator<Jwt> jwtValidator = mock(OAuth2TokenValidator.class);
		given(jwtValidator.validate(any(Jwt.class))).willReturn(OAuth2TokenValidatorResult.failure(failure));
		this.jwtDecoder.setJwtValidator(jwtValidator);
		assertThatExceptionOfType(JwtValidationException.class).isThrownBy(() -> this.jwtDecoder.decode(SIGNED_JWT))
				.withMessageContaining("mock-description");
	}

	@Test
	public void decodeWhenJwtValidationHasTwoErrorsThenJwtExceptionMessageShowsFirstError() {
		OAuth2Error firstFailure = new OAuth2Error("mock-error", "mock-description", "mock-uri");
		OAuth2Error secondFailure = new OAuth2Error("another-error", "another-description", "another-uri");
		OAuth2TokenValidatorResult result = OAuth2TokenValidatorResult.failure(firstFailure, secondFailure);
		OAuth2TokenValidator<Jwt> jwtValidator = mock(OAuth2TokenValidator.class);
		given(jwtValidator.validate(any(Jwt.class))).willReturn(result);
		this.jwtDecoder.setJwtValidator(jwtValidator);
		assertThatExceptionOfType(JwtValidationException.class).isThrownBy(() -> this.jwtDecoder.decode(SIGNED_JWT))
				.withMessageContaining("mock-description").satisfies((ex) -> assertThat(ex)
						.hasFieldOrPropertyWithValue("errors", Arrays.asList(firstFailure, secondFailure)));
	}

	@Test
	public void decodeWhenReadingErrorPickTheFirstErrorMessage() {
		OAuth2TokenValidator<Jwt> jwtValidator = mock(OAuth2TokenValidator.class);
		this.jwtDecoder.setJwtValidator(jwtValidator);
		OAuth2Error errorEmpty = new OAuth2Error("mock-error", "", "mock-uri");
		OAuth2Error error = new OAuth2Error("mock-error", "mock-description", "mock-uri");
		OAuth2Error error2 = new OAuth2Error("mock-error-second", "mock-description-second", "mock-uri-second");
		OAuth2TokenValidatorResult result = OAuth2TokenValidatorResult.failure(errorEmpty, error, error2);
		given(jwtValidator.validate(any(Jwt.class))).willReturn(result);
		Assertions.assertThatExceptionOfType(JwtValidationException.class)
				.isThrownBy(() -> this.jwtDecoder.decode(SIGNED_JWT)).withMessageContaining("mock-description");
	}

	@Test
	public void decodeWhenUsingSignedJwtThenReturnsClaimsGivenByClaimSetConverter() {
		Converter<Map<String, Object>, Map<String, Object>> claimSetConverter = mock(Converter.class);
		given(claimSetConverter.convert(any(Map.class))).willReturn(Collections.singletonMap("custom", "value"));
		this.jwtDecoder.setClaimSetConverter(claimSetConverter);
		Jwt jwt = this.jwtDecoder.decode(SIGNED_JWT);
		assertThat(jwt.getClaims().size()).isEqualTo(1);
		assertThat(jwt.getClaims().get("custom")).isEqualTo("value");
	}

	// gh-7885
	@Test
	public void decodeWhenClaimSetConverterFailsThenBadJwtException() {
		Converter<Map<String, Object>, Map<String, Object>> claimSetConverter = mock(Converter.class);
		this.jwtDecoder.setClaimSetConverter(claimSetConverter);
		given(claimSetConverter.convert(any(Map.class))).willThrow(new IllegalArgumentException("bad conversion"));
		assertThatExceptionOfType(BadJwtException.class).isThrownBy(() -> this.jwtDecoder.decode(SIGNED_JWT));
	}

	@Test
	public void decodeWhenSignedThenOk() {
		NimbusJwtDecoder jwtDecoder = new NimbusJwtDecoder(withSigning(JWK_SET));
		Jwt jwt = jwtDecoder.decode(SIGNED_JWT);
		assertThat(jwt.containsClaim(JwtClaimNames.EXP)).isNotNull();
	}

	@Test
	public void decodeWhenJwkResponseIsMalformedThenReturnsStockException() {
		NimbusJwtDecoder jwtDecoder = new NimbusJwtDecoder(withSigning(MALFORMED_JWK_SET));
		assertThatExceptionOfType(JwtException.class).isThrownBy(() -> jwtDecoder.decode(SIGNED_JWT))
				.isNotInstanceOf(BadJwtException.class)
				.withMessage("An error occurred while attempting to decode the Jwt: Malformed Jwk set");
	}

	@Test
	public void decodeWhenJwkEndpointIsUnresponsiveThenReturnsJwtException() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			String jwkSetUri = server.url("/.well-known/jwks.json").toString();
			NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
			server.shutdown();
			assertThatExceptionOfType(JwtException.class).isThrownBy(() -> jwtDecoder.decode(SIGNED_JWT))
					.isNotInstanceOf(BadJwtException.class)
					.withMessageContaining("An error occurred while attempting to decode the Jwt");
		}
	}

	@Test
	public void decodeWhenJwkEndpointIsUnresponsiveAndCacheIsConfiguredThenReturnsJwtException() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			Cache cache = new ConcurrentMapCache("test-jwk-set-cache");
			String jwkSetUri = server.url("/.well-known/jwks.json").toString();
			NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).cache(cache).build();
			server.shutdown();
			assertThatExceptionOfType(JwtException.class).isThrownBy(() -> jwtDecoder.decode(SIGNED_JWT))
					.isNotInstanceOf(BadJwtException.class)
					.withMessageContaining("An error occurred while attempting to decode the Jwt");
		}
	}

	@Test
	public void withJwkSetUriWhenNullOrEmptyThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> NimbusJwtDecoder.withJwkSetUri(null));
	}

	@Test
	public void jwsAlgorithmWhenNullThenThrowsException() {
		NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder builder = NimbusJwtDecoder.withJwkSetUri(JWK_SET_URI);
		assertThatIllegalArgumentException().isThrownBy(() -> builder.jwsAlgorithm(null));
	}

	@Test
	public void restOperationsWhenNullThenThrowsException() {
		NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder builder = NimbusJwtDecoder.withJwkSetUri(JWK_SET_URI);
		assertThatIllegalArgumentException().isThrownBy(() -> builder.restOperations(null));
	}

	@Test
	public void cacheWhenNullThenThrowsException() {
		NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder builder = NimbusJwtDecoder.withJwkSetUri(JWK_SET_URI);
		assertThatIllegalArgumentException().isThrownBy(() -> builder.cache(null));
	}

	@Test
	public void withPublicKeyWhenNullThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> NimbusJwtDecoder.withPublicKey(null));
	}

	@Test
	public void buildWhenSignatureAlgorithmMismatchesKeyTypeThenThrowsException() {
		Assertions.assertThatCode(
				() -> NimbusJwtDecoder.withPublicKey(key()).signatureAlgorithm(SignatureAlgorithm.ES256).build())
				.isInstanceOf(IllegalStateException.class);
	}

	@Test
	public void decodeWhenUsingPublicKeyThenSuccessfullyDecodes() throws Exception {
		NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(key()).build();
		assertThat(decoder.decode(RS256_SIGNED_JWT)).extracting(Jwt::getSubject).isEqualTo("test-subject");
	}

	@Test
	public void decodeWhenUsingPublicKeyWithRs512ThenSuccessfullyDecodes() throws Exception {
		NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(key()).signatureAlgorithm(SignatureAlgorithm.RS512)
				.build();
		assertThat(decoder.decode(RS512_SIGNED_JWT)).extracting(Jwt::getSubject).isEqualTo("test-subject");
	}

	// gh-7049
	@Test
	public void decodeWhenUsingPublicKeyWithKidThenStillUsesKey() throws Exception {
		RSAPublicKey publicKey = TestKeys.DEFAULT_PUBLIC_KEY;
		RSAPrivateKey privateKey = TestKeys.DEFAULT_PRIVATE_KEY;
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("one").build();
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("test-subject")
				.expirationTime(Date.from(Instant.now().plusSeconds(60))).build();
		SignedJWT signedJwt = signedJwt(privateKey, header, claimsSet);
		NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey)
				.signatureAlgorithm(SignatureAlgorithm.RS256).build();
		assertThat(decoder.decode(signedJwt.serialize())).extracting(Jwt::getSubject).isEqualTo("test-subject");
	}

	@Test
	public void decodeWhenSignatureMismatchesAlgorithmThenThrowsException() throws Exception {
		NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(key()).signatureAlgorithm(SignatureAlgorithm.RS512)
				.build();
		assertThatExceptionOfType(BadJwtException.class).isThrownBy(() -> decoder.decode(RS256_SIGNED_JWT));
	}

	// gh-8730
	@Test
	public void withPublicKeyWhenUsingCustomTypeHeaderThenSuccessfullyDecodes() throws Exception {
		RSAPublicKey publicKey = TestKeys.DEFAULT_PUBLIC_KEY;
		RSAPrivateKey privateKey = TestKeys.DEFAULT_PRIVATE_KEY;
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(new JOSEObjectType("JWS")).build();
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().expirationTime(Date.from(Instant.now().plusSeconds(60)))
				.build();
		SignedJWT signedJwt = signedJwt(privateKey, header, claimsSet);
		NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey)
				.signatureAlgorithm(SignatureAlgorithm.RS256)
				.jwtProcessorCustomizer(
						(p) -> p.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("JWS"))))
				.build();
		assertThat(decoder.decode(signedJwt.serialize()).containsClaim(JwtClaimNames.EXP)).isNotNull();
	}

	@Test
	public void withPublicKeyWhenJwtProcessorCustomizerNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> NimbusJwtDecoder.withPublicKey(key()).jwtProcessorCustomizer(null))
				.withMessage("jwtProcessorCustomizer cannot be null");
	}

	@Test
	public void withSecretKeyWhenNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> NimbusJwtDecoder.withSecretKey(null))
				.withMessage("secretKey cannot be null");
	}

	@Test
	public void withSecretKeyWhenMacAlgorithmNullThenThrowsIllegalArgumentException() {
		SecretKey secretKey = TestKeys.DEFAULT_SECRET_KEY;
		assertThatIllegalArgumentException()
				.isThrownBy(() -> NimbusJwtDecoder.withSecretKey(secretKey).macAlgorithm(null))
				.withMessage("macAlgorithm cannot be null");
	}

	@Test
	public void decodeWhenUsingSecretKeyThenSuccessfullyDecodes() throws Exception {
		SecretKey secretKey = TestKeys.DEFAULT_SECRET_KEY;
		MacAlgorithm macAlgorithm = MacAlgorithm.HS256;
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("test-subject")
				.expirationTime(Date.from(Instant.now().plusSeconds(60))).build();
		SignedJWT signedJWT = signedJwt(secretKey, macAlgorithm, claimsSet);
		NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(secretKey).macAlgorithm(macAlgorithm).build();
		assertThat(decoder.decode(signedJWT.serialize())).extracting(Jwt::getSubject).isEqualTo("test-subject");
	}

	@Test
	public void decodeWhenUsingSecretKeyAndIncorrectAlgorithmThenThrowsJwtException() throws Exception {
		SecretKey secretKey = TestKeys.DEFAULT_SECRET_KEY;
		MacAlgorithm macAlgorithm = MacAlgorithm.HS256;
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("test-subject")
				.expirationTime(Date.from(Instant.now().plusSeconds(60))).build();
		SignedJWT signedJWT = signedJwt(secretKey, macAlgorithm, claimsSet);
		NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(secretKey).macAlgorithm(MacAlgorithm.HS512).build();
		assertThatExceptionOfType(BadJwtException.class).isThrownBy(() -> decoder.decode(signedJWT.serialize()))
				.withMessageContaining("Unsupported algorithm of HS256");
	}

	// gh-7056
	@Test
	public void decodeWhenUsingSecertKeyWithKidThenStillUsesKey() throws Exception {
		SecretKey secretKey = TestKeys.DEFAULT_SECRET_KEY;
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("one").build();
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("test-subject")
				.expirationTime(Date.from(Instant.now().plusSeconds(60))).build();
		SignedJWT signedJwt = signedJwt(secretKey, header, claimsSet);
		NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(secretKey).macAlgorithm(MacAlgorithm.HS256).build();
		assertThat(decoder.decode(signedJwt.serialize())).extracting(Jwt::getSubject).isEqualTo("test-subject");
	}

	// gh-8730
	@Test
	public void withSecretKeyWhenUsingCustomTypeHeaderThenSuccessfullyDecodes() throws Exception {
		SecretKey secretKey = TestKeys.DEFAULT_SECRET_KEY;
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).type(new JOSEObjectType("JWS")).build();
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().expirationTime(Date.from(Instant.now().plusSeconds(60)))
				.build();
		SignedJWT signedJwt = signedJwt(secretKey, header, claimsSet);
		NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(secretKey).macAlgorithm(MacAlgorithm.HS256)
				.jwtProcessorCustomizer(
						(p) -> p.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("JWS"))))
				.build();
		assertThat(decoder.decode(signedJwt.serialize()).containsClaim(JwtClaimNames.EXP)).isNotNull();
	}

	@Test
	public void withSecretKeyWhenJwtProcessorCustomizerNullThenThrowsIllegalArgumentException() {
		SecretKey secretKey = TestKeys.DEFAULT_SECRET_KEY;
		assertThatIllegalArgumentException()
				.isThrownBy(() -> NimbusJwtDecoder.withSecretKey(secretKey).jwtProcessorCustomizer(null))
				.withMessage("jwtProcessorCustomizer cannot be null");
	}

	@Test
	public void jwsKeySelectorWhenNoAlgorithmThenReturnsRS256Selector() {
		JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);
		JWSKeySelector<SecurityContext> jwsKeySelector = NimbusJwtDecoder.withJwkSetUri(JWK_SET_URI)
				.jwsKeySelector(jwkSource);
		assertThat(jwsKeySelector instanceof JWSVerificationKeySelector);
		JWSVerificationKeySelector<?> jwsVerificationKeySelector = (JWSVerificationKeySelector<?>) jwsKeySelector;
		assertThat(jwsVerificationKeySelector.isAllowed(JWSAlgorithm.RS256)).isTrue();
	}

	@Test
	public void jwsKeySelectorWhenOneAlgorithmThenReturnsSingleSelector() {
		JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);
		JWSKeySelector<SecurityContext> jwsKeySelector = NimbusJwtDecoder.withJwkSetUri(JWK_SET_URI)
				.jwsAlgorithm(SignatureAlgorithm.RS512).jwsKeySelector(jwkSource);
		assertThat(jwsKeySelector instanceof JWSVerificationKeySelector);
		JWSVerificationKeySelector<?> jwsVerificationKeySelector = (JWSVerificationKeySelector<?>) jwsKeySelector;
		assertThat(jwsVerificationKeySelector.isAllowed(JWSAlgorithm.RS512)).isTrue();
	}

	@Test
	public void jwsKeySelectorWhenMultipleAlgorithmThenReturnsCompositeSelector() {
		JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);
		JWSKeySelector<SecurityContext> jwsKeySelector = NimbusJwtDecoder.withJwkSetUri(JWK_SET_URI)
				.jwsAlgorithm(SignatureAlgorithm.RS256).jwsAlgorithm(SignatureAlgorithm.RS512)
				.jwsKeySelector(jwkSource);
		assertThat(jwsKeySelector instanceof JWSVerificationKeySelector);
		JWSVerificationKeySelector<?> jwsAlgorithmMapKeySelector = (JWSVerificationKeySelector<?>) jwsKeySelector;
		assertThat(jwsAlgorithmMapKeySelector.isAllowed(JWSAlgorithm.RS256)).isTrue();
		assertThat(jwsAlgorithmMapKeySelector.isAllowed(JWSAlgorithm.RS512)).isTrue();
	}

	// gh-7290
	@Test
	public void decodeWhenJwkSetRequestedThenAcceptHeaderJsonAndJwkSetJson() {
		RestOperations restOperations = mock(RestOperations.class);
		given(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.willReturn(new ResponseEntity<>(JWK_SET, HttpStatus.OK));
		JWTProcessor<SecurityContext> processor = NimbusJwtDecoder.withJwkSetUri(JWK_SET_URI)
				.restOperations(restOperations).processor();
		NimbusJwtDecoder jwtDecoder = new NimbusJwtDecoder(processor);
		jwtDecoder.decode(SIGNED_JWT);
		ArgumentCaptor<RequestEntity> requestEntityCaptor = ArgumentCaptor.forClass(RequestEntity.class);
		verify(restOperations).exchange(requestEntityCaptor.capture(), eq(String.class));
		List<MediaType> acceptHeader = requestEntityCaptor.getValue().getHeaders().getAccept();
		assertThat(acceptHeader).contains(MediaType.APPLICATION_JSON, APPLICATION_JWK_SET_JSON);
	}

	@Test
	public void decodeWhenCacheThenStoreRetrievedJwkSetToCache() {
		Cache cache = new ConcurrentMapCache("test-jwk-set-cache");
		RestOperations restOperations = mock(RestOperations.class);
		given(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.willReturn(new ResponseEntity<>(JWK_SET, HttpStatus.OK));
		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(JWK_SET_URI).restOperations(restOperations)
				.cache(cache).build();
		jwtDecoder.decode(SIGNED_JWT);
		assertThat(cache.get(JWK_SET_URI, String.class)).isEqualTo(JWK_SET);
		ArgumentCaptor<RequestEntity> requestEntityCaptor = ArgumentCaptor.forClass(RequestEntity.class);
		verify(restOperations).exchange(requestEntityCaptor.capture(), eq(String.class));
		verifyNoMoreInteractions(restOperations);
		List<MediaType> acceptHeader = requestEntityCaptor.getValue().getHeaders().getAccept();
		assertThat(acceptHeader).contains(MediaType.APPLICATION_JSON, APPLICATION_JWK_SET_JSON);
	}

	@Test
	public void decodeWhenCacheThenRetrieveFromCache() {
		RestOperations restOperations = mock(RestOperations.class);
		Cache cache = mock(Cache.class);
		given(cache.get(eq(JWK_SET_URI), any(Callable.class))).willReturn(JWK_SET);
		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(JWK_SET_URI).cache(cache)
				.restOperations(restOperations).build();
		jwtDecoder.decode(SIGNED_JWT);
		verify(cache).get(eq(JWK_SET_URI), any(Callable.class));
		verifyNoMoreInteractions(cache);
		verifyNoInteractions(restOperations);
	}

	@Test
	public void decodeWhenCacheIsConfiguredAndValueLoaderErrorsThenThrowsJwtException() {
		Cache cache = new ConcurrentMapCache("test-jwk-set-cache");
		RestOperations restOperations = mock(RestOperations.class);
		given(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.willThrow(new RestClientException("Cannot retrieve JWK Set"));
		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(JWK_SET_URI).restOperations(restOperations)
				.cache(cache).build();
		assertThatExceptionOfType(JwtException.class).isThrownBy(() -> jwtDecoder.decode(SIGNED_JWT))
				.isNotInstanceOf(BadJwtException.class)
				.withMessageContaining("An error occurred while attempting to decode the Jwt");
	}

	// gh-8730
	@Test
	public void withJwkSetUriWhenUsingCustomTypeHeaderThenRefuseOmittedType() throws Exception {
		RestOperations restOperations = mock(RestOperations.class);
		given(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.willReturn(new ResponseEntity<>(JWK_SET, HttpStatus.OK));
		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(JWK_SET_URI).restOperations(restOperations)
				.jwtProcessorCustomizer(
						(p) -> p.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("JWS"))))
				.build();
		assertThatExceptionOfType(BadJwtException.class).isThrownBy(() -> jwtDecoder.decode(SIGNED_JWT))
				.withMessageContaining("An error occurred while attempting to decode the Jwt: "
						+ "Required JOSE header \"typ\" (type) parameter is missing");
	}

	@Test
	public void withJwkSetUriWhenJwtProcessorCustomizerNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> NimbusJwtDecoder.withJwkSetUri(JWK_SET_URI).jwtProcessorCustomizer(null))
				.withMessage("jwtProcessorCustomizer cannot be null");
	}

	private RSAPublicKey key() throws InvalidKeySpecException {
		byte[] decoded = Base64.getDecoder().decode(VERIFY_KEY.getBytes());
		EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
		return (RSAPublicKey) kf.generatePublic(spec);
	}

	private SignedJWT signedJwt(SecretKey secretKey, MacAlgorithm jwsAlgorithm, JWTClaimsSet claimsSet)
			throws Exception {
		return signedJwt(secretKey, new JWSHeader(JWSAlgorithm.parse(jwsAlgorithm.getName())), claimsSet);
	}

	private SignedJWT signedJwt(SecretKey secretKey, JWSHeader header, JWTClaimsSet claimsSet) throws Exception {
		JWSSigner signer = new MACSigner(secretKey);
		return signedJwt(signer, header, claimsSet);
	}

	private SignedJWT signedJwt(PrivateKey privateKey, JWSHeader header, JWTClaimsSet claimsSet) throws Exception {
		JWSSigner signer = new RSASSASigner(privateKey);
		return signedJwt(signer, header, claimsSet);
	}

	private SignedJWT signedJwt(JWSSigner signer, JWSHeader header, JWTClaimsSet claimsSet) throws Exception {
		SignedJWT signedJWT = new SignedJWT(header, claimsSet);
		signedJWT.sign(signer);
		return signedJWT;
	}

	private static JWTProcessor<SecurityContext> withSigning(String jwkResponse) {
		RestOperations restOperations = mock(RestOperations.class);
		given(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.willReturn(new ResponseEntity<>(jwkResponse, HttpStatus.OK));
		return NimbusJwtDecoder.withJwkSetUri(JWK_SET_URI).restOperations(restOperations).processor();
	}

	private static JWTProcessor<SecurityContext> withoutSigning() {
		return new MockJwtProcessor();
	}

	private static class MockJwtProcessor extends DefaultJWTProcessor<SecurityContext> {

		@Override
		public JWTClaimsSet process(SignedJWT signedJWT, SecurityContext context) throws BadJOSEException {
			try {
				return signedJWT.getJWTClaimsSet();
			}
			catch (ParseException ex) {
				// Payload not a JSON object
				throw new BadJWTException(ex.getMessage(), ex);
			}
		}

	}

}
