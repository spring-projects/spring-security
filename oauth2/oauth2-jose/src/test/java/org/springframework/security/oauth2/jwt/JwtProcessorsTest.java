/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.jwt;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.JWTProcessor;
import org.junit.Test;

import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestOperations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
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
	private static final String JWK_SET = "{\"keys\":[{\"p\":\"49neceJFs8R6n7WamRGy45F5Tv0YM-R2ODK3eSBUSLOSH2tAqjEVKOkLE5fiNA3ygqq15NcKRadB2pTVf-Yb5ZIBuKzko8bzYIkIqYhSh_FAdEEr0vHF5fq_yWSvc6swsOJGqvBEtuqtJY027u-G2gAQasCQdhyejer68zsTn8M\",\"kty\":\"RSA\",\"q\":\"tWR-ysspjZ73B6p2vVRVyHwP3KQWL5KEQcdgcmMOE_P_cPs98vZJfLhxobXVmvzuEWBpRSiqiuyKlQnpstKt94Cy77iO8m8ISfF3C9VyLWXi9HUGAJb99irWABFl3sNDff5K2ODQ8CmuXLYM25OwN3ikbrhEJozlXg_NJFSGD4E\",\"d\":\"FkZHYZlw5KSoqQ1i2RA2kCUygSUOf1OqMt3uomtXuUmqKBm_bY7PCOhmwbvbn4xZYEeHuTR8Xix-0KpHe3NKyWrtRjkq1T_un49_1LLVUhJ0dL-9_x0xRquVjhl_XrsRXaGMEHs8G9pLTvXQ1uST585gxIfmCe0sxPZLvwoic-bXf64UZ9BGRV3lFexWJQqCZp2S21HfoU7wiz6kfLRNi-K4xiVNB1gswm_8o5lRuY7zB9bRARQ3TS2G4eW7p5sxT3CgsGiQD3_wPugU8iDplqAjgJ5ofNJXZezoj0t6JMB_qOpbrmAM1EnomIPebSLW7Ky9SugEd6KMdL5lW6AuAQ\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"one\",\"qi\":\"wdkFu_tV2V1l_PWUUimG516Zvhqk2SWDw1F7uNDD-Lvrv_WNRIJVzuffZ8WYiPy8VvYQPJUrT2EXL8P0ocqwlaSTuXctrORcbjwgxDQDLsiZE0C23HYzgi0cofbScsJdhcBg7d07LAf7cdJWG0YVl1FkMCsxUlZ2wTwHfKWf-v4\",\"dp\":\"uwnPxqC-IxG4r33-SIT02kZC1IqC4aY7PWq0nePiDEQMQWpjjNH50rlq9EyLzbtdRdIouo-jyQXB01K15-XXJJ60dwrGLYNVqfsTd0eGqD1scYJGHUWG9IDgCsxyEnuG3s0AwbW2UolWVSsU2xMZGb9PurIUZECeD1XDZwMp2s0\",\"dq\":\"hra786AunB8TF35h8PpROzPoE9VJJMuLrc6Esm8eZXMwopf0yhxfN2FEAvUoTpLJu93-UH6DKenCgi16gnQ0_zt1qNNIVoRfg4rw_rjmsxCYHTVL3-RDeC8X_7TsEySxW0EgFTHh-nr6I6CQrAJjPM88T35KHtdFATZ7BCBB8AE\",\"n\":\"oXJ8OyOv_eRnce4akdanR4KYRfnC2zLV4uYNQpcFn6oHL0dj7D6kxQmsXoYgJV8ZVDn71KGmuLvolxsDncc2UrhyMBY6DVQVgMSVYaPCTgW76iYEKGgzTEw5IBRQL9w3SRJWd3VJTZZQjkXef48Ocz06PGF3lhbz4t5UEZtdF4rIe7u-977QwHuh7yRPBQ3sII-cVoOUMgaXB9SHcGF2iZCtPzL_IffDUcfhLQteGebhW8A6eUHgpD5A1PQ-JCw_G7UOzZAjjDjtNM2eqm8j-Ms_gqnm4MiCZ4E-9pDN77CAAPVN7kuX6ejs9KBXpk01z48i9fORYk9u7rAkh1HuQw\"}]}";
	private static final String SIGNED_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJzY3AiOlsibWVzc2FnZTpyZWFkIl0sImV4cCI6NDY4Mzg5Nzc3Nn0.LtMVtIiRIwSyc3aX35Zl0JVwLTcQZAB3dyBOMHNaHCKUljwMrf20a_gT79LfhjDzE_fUVUmFiAO32W1vFnYpZSVaMDUgeIOIOpxfoe9shj_uYenAwIS-_UxqGVIJiJoXNZh_MK80ShNpvsQwamxWEEOAMBtpWNiVYNDMdfgho9n3o5_Z7Gjy8RLBo1tbDREbO9kTFwGIxm_EYpezmRCRq4w1DdS6UDW321hkwMxPnCMSWOvp-hRpmgY2yjzLgPJ6Aucmg9TJ8jloAP1DjJoF1gRR7NTAk8LOGkSjTzVYDYMbCF51YdpojhItSk80YzXiEsv1mTz4oMM49jXBmfXFMA";
	private static final String JWK_SET_URI = "http://issuer/.well-known/jwks.json";

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
		assertThat(processor.process(SIGNED_JWT, null))
				.extracting(JWTClaimsSet::getExpirationTime)
				.isNotNull();
		verify(restOperations).exchange(any(RequestEntity.class), eq(String.class));
	}

	private static RestOperations mockJwkSetResponse(String response) {
		RestOperations restOperations = mock(RestOperations.class);
		when(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.thenReturn(new ResponseEntity<>(response, HttpStatus.OK));
		return restOperations;
	}
}
