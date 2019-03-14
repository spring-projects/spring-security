/*
 * Copyright 2002-2018 the original author or authors.
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
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.JWTProcessor;
import org.junit.BeforeClass;
import org.junit.Test;

import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.web.client.RestOperations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.jwt.JwtProcessors.withJwkSetUri;

/**
 * Tests for {@link JwtProcessors}
 */
public class JwtProcessorsTest {
	private static final String JWK_SET = "{\"keys\":[{\"p\":\"5VhDhCcOp9D3krJi2W2uF-LPovIKqtU59Jdt_gF6iwPw_0Bgo8UlbFRv3HdnVYUExLdkvHOoA9bmbkV0w_6TUwLP65PKPu6P8JfeWsIuGi3wY91_CsfahxGmVZxlZookBUIMMnylvM9fGR6-daNgkl31CKqDpkJt9XF35yjVpbM\",\"kty\":\"RSA\",\"q\":\"v3yrgOhimojmLVsLBdynmw_pfAlZPw2eXVzoJ514xP94UZJQRY_NOUjYV0O9Vqict_Qv42sUa-uurY8n_0Btslt--iJsMyTHYMIKjbyeFAqAGFuXYbQPnorEOkuZhT1NIBZhlLLuKSD8DVCtsEv2EVgBTwyzFJ6QbXLqVpNUvZs\",\"d\":\"ZyjCopsw7TszSV4qMIyunb0PaGfHbQ_0LJcAxhNwQsf3MYR6j0J9k1GVxq2SjpRylgKJg8CKjySaU4frewH7MEaNLNdfR2_XMFSKW3KFggdNRtW1TFwjcHfpBLTvB3MEaTx56Sohn0eXqd_Wa2EAfRiLjllwOeqwXqgdSXdvKfkkmV2DBZ2h100wLJB87Y5kvlGvbNDs0KgTFaPWRZkCQz3CGhGPDyTJVwzgJvIxbHgzl9DnW6FlgrP_DZmyfGbJ833FZSiBczTQGDWT7euR3h491fKPCHTXjdULtU1578NldRAo8SOXH4ThXXA_kwKafIGlKx5LZPNwMWgNuVvE6Q\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"one\",\"qi\":\"eaGTNLhJf1K82YqB6VKrYWz1hxsKnjRBg-V-kuWJXvW7HQsLFKx56kXy_ximz_IQDZOO3F-rW_7Saz3RvWuFt_Yq7sRcLCMtpiDRbZ-nGDgHxQHedtLoalLLPmJkMMsZwZzXf9l6LO6a8r30lrC_C-kPY5K7lz97ZToKeper7c8\",\"dp\":\"QQJ4-O_dTqKEWvfn3zwg2jJ3qvezIGOarwNxsUuYAenXGXOVMTcD-aYhozvRdcNj66MUkfqyyIvU-7MCe0AhYKluaJeW_6m98XQLGmzqho85EgXKKjMmdZ0CKkhP0fYcacUkEfeVP2UEzukREeWCzVqGx7MV6D3yT12foE3J6dM\",\"dq\":\"PsH2V5ZSEsHBZqYLE83ApMJvTHan6FFnUMQNVkZ2-WGdJmbkphe-NAMa3GbYHBnA201NkKRcmg4xPrLHchHEogr4r7QucAiiy6Rs3w0tZfYXC2ShVaU05Uoni8-RLijsKRMMwjZudc5YrWh-tGQA7qhALY9E9gIN5cEe6mb5A_c\",\"n\":\"q4yKxb6SNePdDmQi9xFCrP6QvHosErQzryknQTTTffs0t3cy3Er3lIceuhZ7yQNSCDfPFqG8GoyoKhuChRiA5D-J2ab7bqTa1QJKfnCyERoscftgN2fXPHjHoiKbpGV2tMVw8mXl__tePOAiKbMJaBUnlAvJgkk1rVm08dSwpLC1sr2M19euf9jwnRGkMRZuhp9iCPgECRke5T8Ixpv0uQjSmGHnWUKTFlbj8sM83suROR1Ue64JSGScANc5vk3huJ_J97qTC-K2oKj6L8d9O8dpc4obijEOJwpydNvTYDgbiivYeSB00KS9jlBkQ5B2QqLvLVEygDl3dp59nGx6YQ\"}]}";
	private static final String JWK_SET_URI = "http://issuer/.well-known/jwks.json";
	private static final String RS512_SIGNED_JWT = "eyJhbGciOiJSUzUxMiJ9.eyJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJleHAiOjE5NzQzMjYxMTl9.LKAx-60EBfD7jC1jb1eKcjO4uLvf3ssISV-8tN-qp7gAjSvKvj4YA9-V2mIb6jcS1X_xGmNy6EIimZXpWaBR3nJmeu-jpe85u4WaW2Ztr8ecAi-dTO7ZozwdtljKuBKKvj4u1nF70zyCNl15AozSG0W1ASrjUuWrJtfyDG6WoZ8VfNMuhtU-xUYUFvscmeZKUYQcJ1KS-oV5tHeF8aNiwQoiPC_9KXCOZtNEJFdq6-uzFdHxvOP2yex5Gbmg5hXonauIFXG2ZPPGdXzm-5xkhBpgM8U7A_6wb3So8wBvLYYm2245QUump63AJRAy8tQpwt4n9MvQxQgS3z9R-NK92A";
	private static final String RS256_SIGNED_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJleHAiOjE5NzQzMjYzMzl9.CT-H2OWEqmSs1NWmnta5ealLFvM8OlbQTjGhfRcKLNxrTrzsOkqBJl-AN3k16BQU7mS32o744TiiZ29NcDlxPsr1MqTlN86-dobPiuNIDLp3A1bOVdXMcVFuMYkrNv0yW0tGS9OjEqsCCuZDkZ1by6AhsHLbGwRY-6AQdcRouZygGpOQu1hNun5j8q5DpSTY4AXKARIFlF-O3OpVbPJ0ebr3Ki-i3U9p_55H0e4-wx2bqcApWlqgofl1I8NKWacbhZgn81iibup2W7E0CzCzh71u1Mcy3xk1sYePx-dwcxJnHmxJReBBWjJZEAeCrkbnn_OCuo2fA-EQyNJtlN5F2w";
	private static final String VERIFY_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq4yKxb6SNePdDmQi9xFCrP6QvHosErQzryknQTTTffs0t3cy3Er3lIceuhZ7yQNSCDfPFqG8GoyoKhuChRiA5D+J2ab7bqTa1QJKfnCyERoscftgN2fXPHjHoiKbpGV2tMVw8mXl//tePOAiKbMJaBUnlAvJgkk1rVm08dSwpLC1sr2M19euf9jwnRGkMRZuhp9iCPgECRke5T8Ixpv0uQjSmGHnWUKTFlbj8sM83suROR1Ue64JSGScANc5vk3huJ/J97qTC+K2oKj6L8d9O8dpc4obijEOJwpydNvTYDgbiivYeSB00KS9jlBkQ5B2QqLvLVEygDl3dp59nGx6YQIDAQAB";

	private static KeyFactory kf;

	@BeforeClass
	public static void keyFactory() throws NoSuchAlgorithmException {
		kf = KeyFactory.getInstance("RSA");
	}

	@Test
	public void withJwkSetUriWhenNullOrEmptyThenThrowsException() {
		assertThatCode(() -> withJwkSetUri(null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void jwsAlgorithmWhenNullOrEmptyThenThrowsException() {
		JwtProcessors.JwkSetUriJwtProcessorBuilder builder = withJwkSetUri(JWK_SET_URI);
		assertThatCode(() -> builder.jwsAlgorithm(null)).isInstanceOf(IllegalArgumentException.class);
		assertThatCode(() -> builder.jwsAlgorithm("")).isInstanceOf(IllegalArgumentException.class);
		assertThatCode(() -> builder.jwsAlgorithm("RS4096")).doesNotThrowAnyException();
	}

	@Test
	public void restOperationsWhenNullThenThrowsException() {
		JwtProcessors.JwkSetUriJwtProcessorBuilder builder = withJwkSetUri(JWK_SET_URI);
		assertThatCode(() -> builder.restOperations(null)).isInstanceOf(IllegalArgumentException.class);
	}

	// gh-5603
	@Test
	public void processWhenSignedThenOk() throws Exception {
		RestOperations restOperations = mockJwkSetResponse(JWK_SET);
		JWTProcessor<SecurityContext> processor =
				withJwkSetUri(JWK_SET_URI).restOperations(restOperations).build();
		assertThat(processor.process(RS256_SIGNED_JWT, null))
				.extracting(JWTClaimsSet::getExpirationTime)
				.isNotNull();
		verify(restOperations).exchange(any(RequestEntity.class), eq(String.class));
	}

	@Test
	public void withPublicKeyWhenNullThenThrowsException() {
		assertThatThrownBy(() -> JwtProcessors.withPublicKey(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenSignatureAlgorithmMismatchesKeyTypeThenThrowsException() {
		assertThatCode(() -> JwtProcessors.withPublicKey(key())
				.jwsAlgorithm(JwsAlgorithms.ES256)
				.build())
				.isInstanceOf(IllegalStateException.class);
	}

	@Test
	public void processWhenUsingPublicKeyThenSuccessfullyDecodes() throws Exception {
		JWTProcessor<SecurityContext> processor = JwtProcessors.withPublicKey(key()).build();
		assertThat(processor.process(RS256_SIGNED_JWT, null))
				.extracting(JWTClaimsSet::getSubject)
				.isEqualTo("test-subject");
	}

	@Test
	public void processWhenUsingPublicKeyWithRs512ThenSuccessfullyDecodes() throws Exception {
		JWTProcessor<SecurityContext> processor = JwtProcessors
				.withPublicKey(key()).jwsAlgorithm(JwsAlgorithms.RS512).build();
		assertThat(processor.process(RS512_SIGNED_JWT, null))
				.extracting(JWTClaimsSet::getSubject)
				.isEqualTo("test-subject");
	}

	@Test
	public void processWhenSignatureMismatchesAlgorithmThenThrowsException() throws Exception {
		JWTProcessor<SecurityContext> processor = JwtProcessors
				.withPublicKey(key()).jwsAlgorithm(JwsAlgorithms.RS512).build();
		assertThatCode(() -> processor.process(RS256_SIGNED_JWT, null))
				.isInstanceOf(BadJOSEException.class);
	}

	private RSAPublicKey key() throws InvalidKeySpecException {
		byte[] decoded = Base64.getDecoder().decode(VERIFY_KEY.getBytes());
		EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
		return (RSAPublicKey) kf.generatePublic(spec);
	}

	private static RestOperations mockJwkSetResponse(String response) {
		RestOperations restOperations = mock(RestOperations.class);
		when(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.thenReturn(new ResponseEntity<>(response, HttpStatus.OK));
		return restOperations;
	}
}
