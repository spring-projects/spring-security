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

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Tests for {@link JwtDecoders}
 *
 * @author Josh Cummings
 */
public class JwtDecodersTests {
	/**
	 * Contains those parameters required to construct a JwtDecoder as well as any required parameters
	 */
	private static final String DEFAULT_RESPONSE_TEMPLATE =
			"{\n"
					+ "    \"authorization_endpoint\": \"https://example.com/o/oauth2/v2/auth\", \n"
					+ "    \"id_token_signing_alg_values_supported\": [\n"
					+ "        \"RS256\"\n"
					+ "    ], \n"
					+ "    \"issuer\": \"%s\", \n"
					+ "    \"jwks_uri\": \"%s/.well-known/jwks.json\", \n"
					+ "    \"response_types_supported\": [\n"
					+ "        \"code\", \n"
					+ "        \"token\", \n"
					+ "        \"id_token\", \n"
					+ "        \"code token\", \n"
					+ "        \"code id_token\", \n"
					+ "        \"token id_token\", \n"
					+ "        \"code token id_token\", \n"
					+ "        \"none\"\n"
					+ "    ], \n"
					+ "    \"subject_types_supported\": [\n"
					+ "        \"public\"\n"
					+ "    ], \n"
					+ "    \"token_endpoint\": \"https://example.com/oauth2/v4/token\"\n"
					+ "}";

	private static final String JWK_SET = "{\"keys\":[{\"p\":\"49neceJFs8R6n7WamRGy45F5Tv0YM-R2ODK3eSBUSLOSH2tAqjEVKOkLE5fiNA3ygqq15NcKRadB2pTVf-Yb5ZIBuKzko8bzYIkIqYhSh_FAdEEr0vHF5fq_yWSvc6swsOJGqvBEtuqtJY027u-G2gAQasCQdhyejer68zsTn8M\",\"kty\":\"RSA\",\"q\":\"tWR-ysspjZ73B6p2vVRVyHwP3KQWL5KEQcdgcmMOE_P_cPs98vZJfLhxobXVmvzuEWBpRSiqiuyKlQnpstKt94Cy77iO8m8ISfF3C9VyLWXi9HUGAJb99irWABFl3sNDff5K2ODQ8CmuXLYM25OwN3ikbrhEJozlXg_NJFSGD4E\",\"d\":\"FkZHYZlw5KSoqQ1i2RA2kCUygSUOf1OqMt3uomtXuUmqKBm_bY7PCOhmwbvbn4xZYEeHuTR8Xix-0KpHe3NKyWrtRjkq1T_un49_1LLVUhJ0dL-9_x0xRquVjhl_XrsRXaGMEHs8G9pLTvXQ1uST585gxIfmCe0sxPZLvwoic-bXf64UZ9BGRV3lFexWJQqCZp2S21HfoU7wiz6kfLRNi-K4xiVNB1gswm_8o5lRuY7zB9bRARQ3TS2G4eW7p5sxT3CgsGiQD3_wPugU8iDplqAjgJ5ofNJXZezoj0t6JMB_qOpbrmAM1EnomIPebSLW7Ky9SugEd6KMdL5lW6AuAQ\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"one\",\"qi\":\"wdkFu_tV2V1l_PWUUimG516Zvhqk2SWDw1F7uNDD-Lvrv_WNRIJVzuffZ8WYiPy8VvYQPJUrT2EXL8P0ocqwlaSTuXctrORcbjwgxDQDLsiZE0C23HYzgi0cofbScsJdhcBg7d07LAf7cdJWG0YVl1FkMCsxUlZ2wTwHfKWf-v4\",\"dp\":\"uwnPxqC-IxG4r33-SIT02kZC1IqC4aY7PWq0nePiDEQMQWpjjNH50rlq9EyLzbtdRdIouo-jyQXB01K15-XXJJ60dwrGLYNVqfsTd0eGqD1scYJGHUWG9IDgCsxyEnuG3s0AwbW2UolWVSsU2xMZGb9PurIUZECeD1XDZwMp2s0\",\"dq\":\"hra786AunB8TF35h8PpROzPoE9VJJMuLrc6Esm8eZXMwopf0yhxfN2FEAvUoTpLJu93-UH6DKenCgi16gnQ0_zt1qNNIVoRfg4rw_rjmsxCYHTVL3-RDeC8X_7TsEySxW0EgFTHh-nr6I6CQrAJjPM88T35KHtdFATZ7BCBB8AE\",\"n\":\"oXJ8OyOv_eRnce4akdanR4KYRfnC2zLV4uYNQpcFn6oHL0dj7D6kxQmsXoYgJV8ZVDn71KGmuLvolxsDncc2UrhyMBY6DVQVgMSVYaPCTgW76iYEKGgzTEw5IBRQL9w3SRJWd3VJTZZQjkXef48Ocz06PGF3lhbz4t5UEZtdF4rIe7u-977QwHuh7yRPBQ3sII-cVoOUMgaXB9SHcGF2iZCtPzL_IffDUcfhLQteGebhW8A6eUHgpD5A1PQ-JCw_G7UOzZAjjDjtNM2eqm8j-Ms_gqnm4MiCZ4E-9pDN77CAAPVN7kuX6ejs9KBXpk01z48i9fORYk9u7rAkh1HuQw\"}]}";
	private static final String ISSUER_MISMATCH = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvd3Jvbmdpc3N1ZXIiLCJleHAiOjQ2ODcyNTYwNDl9.Ax8LMI6rhB9Pv_CE3kFi1JPuLj9gZycifWrLeDpkObWEEVAsIls9zAhNFyJlG-Oo7up6_mDhZgeRfyKnpSF5GhKJtXJDCzwg0ZDVUE6rS0QadSxsMMGbl7c4y0lG_7TfLX2iWeNJukJj_oSW9KzW4FsBp1BoocWjrreesqQU3fZHbikH-c_Fs2TsAIpHnxflyEzfOFWpJ8D4DtzHXqfvieMwpy42xsPZK3LR84zlasf0Ne1tC_hLHvyHRdAXwn0CMoKxc7-8j0r9Mq8kAzUsPn9If7bMLqGkxUcTPdk5x7opAUajDZx95SXHLmtztNtBa2S6EfPJXuPKG6tM5Wq5Ug";

	private MockWebServer server;
	private String issuer;
	private String jwkSetUri;

	@Before
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		this.issuer = createIssuerFromServer();
		this.jwkSetUri = this.issuer + "/.well-known/jwks.json";
	}

	@After
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void issuerWhenResponseIsTypicalThenReturnedDecoderValidatesIssuer() {
		prepareOpenIdConfigurationResponse();
		this.server.enqueue(new MockResponse().setBody(JWK_SET));

		JwtDecoder decoder = JwtDecoders.fromOidcIssuerLocation(this.issuer);

		assertThatCode(() -> decoder.decode(ISSUER_MISMATCH))
				.isInstanceOf(JwtValidationException.class)
				.hasMessageContaining("This iss claim is not equal to the configured issuer");
	}

	@Test
	public void issuerWhenContainsTrailingSlashThenSuccess() {
		prepareOpenIdConfigurationResponse();
		this.server.enqueue(new MockResponse().setBody(JWK_SET));
		assertThat(JwtDecoders.fromOidcIssuerLocation(this.issuer)).isNotNull();
		assertThat(this.issuer).endsWith("/");
	}

	@Test
	public void issuerWhenResponseIsNonCompliantThenThrowsRuntimeException() {
		prepareOpenIdConfigurationResponse("{ \"missing_required_keys\" : \"and_values\" }");

		assertThatCode(() -> JwtDecoders.fromOidcIssuerLocation(this.issuer))
				.isInstanceOf(RuntimeException.class);
	}

	@Test
	public void issuerWhenResponseIsMalformedThenThrowsRuntimeException() {
		prepareOpenIdConfigurationResponse("malformed");

		assertThatCode(() -> JwtDecoders.fromOidcIssuerLocation(this.issuer))
				.isInstanceOf(RuntimeException.class);
	}

	@Test
	public void issuerWhenRespondingIssuerMismatchesRequestedIssuerThenThrowsIllegalStateException() {
		prepareOpenIdConfigurationResponse();

		assertThatCode(() -> JwtDecoders.fromOidcIssuerLocation(this.issuer + "/wrong"))
				.isInstanceOf(IllegalStateException.class);
	}

	@Test
	public void issuerWhenRequestedIssuerIsUnresponsiveThenThrowsIllegalArgumentException()
			throws Exception {

		this.server.shutdown();

		assertThatCode(() -> JwtDecoders.fromOidcIssuerLocation("https://issuer"))
				.isInstanceOf(IllegalArgumentException.class);
	}

	private void prepareOpenIdConfigurationResponse() {
		String body = String.format(DEFAULT_RESPONSE_TEMPLATE, this.issuer, this.issuer);
		prepareOpenIdConfigurationResponse(body);
	}

	private void prepareOpenIdConfigurationResponse(String body) {
		MockResponse mockResponse = new MockResponse()
				.setBody(body)
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
		this.server.enqueue(mockResponse);
	}

	private String createIssuerFromServer() {
		return this.server.url("").toString();
	}
}
