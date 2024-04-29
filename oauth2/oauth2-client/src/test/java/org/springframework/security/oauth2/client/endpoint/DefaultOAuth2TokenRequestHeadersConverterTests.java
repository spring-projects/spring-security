/*
 * Copyright 2002-2024 the original author or authors.
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

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link DefaultOAuth2TokenRequestHeadersConverter}.
 *
 * @author Steve Riesenberg
 */
public class DefaultOAuth2TokenRequestHeadersConverterTests {

	private static final MediaType APPLICATION_JSON_UTF8 = new MediaType(MediaType.APPLICATION_JSON,
			StandardCharsets.UTF_8);

	private static final MediaType APPLICATION_FORM_URLENCODED_UTF8 = new MediaType(
			MediaType.APPLICATION_FORM_URLENCODED, StandardCharsets.UTF_8);

	private DefaultOAuth2TokenRequestHeadersConverter<OAuth2ClientCredentialsGrantRequest> converter;

	@BeforeEach
	public void setUp() {
		this.converter = new DefaultOAuth2TokenRequestHeadersConverter<>();
	}

	@Test
	public void convertWhenEncodeClientCredentialsTrueThenConvertsWithUrlEncoding() {
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials()
				.clientId("clientId")
				.clientSecret("clientSecret=")
				.build();
		// @formatter:on
		OAuth2ClientCredentialsGrantRequest grantRequest = new OAuth2ClientCredentialsGrantRequest(clientRegistration);
		HttpHeaders defaultHeaders = this.converter.convert(grantRequest);
		assertThat(defaultHeaders.getAccept()).containsExactly(MediaType.APPLICATION_JSON);
		assertThat(defaultHeaders.getContentType()).isEqualTo(MediaType.APPLICATION_FORM_URLENCODED);
		assertThat(defaultHeaders.getFirst(HttpHeaders.AUTHORIZATION))
			.isEqualTo("Basic Y2xpZW50SWQ6Y2xpZW50U2VjcmV0JTNE");
	}

	@Test
	public void convertWhenEncodeClientCredentialsFalseThenConvertsWithoutUrlEncoding() {
		this.converter.setEncodeClientCredentials(false);
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials()
				.clientId("clientId")
				.clientSecret("clientSecret=")
				.build();
		// @formatter:on
		OAuth2ClientCredentialsGrantRequest grantRequest = new OAuth2ClientCredentialsGrantRequest(clientRegistration);
		HttpHeaders defaultHeaders = this.converter.convert(grantRequest);
		assertThat(defaultHeaders.getAccept()).containsExactly(MediaType.APPLICATION_JSON);
		assertThat(defaultHeaders.getContentType()).isEqualTo(MediaType.APPLICATION_FORM_URLENCODED);
		assertThat(defaultHeaders.getFirst(HttpHeaders.AUTHORIZATION))
			.isEqualTo("Basic Y2xpZW50SWQ6Y2xpZW50U2VjcmV0PQ==");
	}

	@Test
	public void convertWhenWithCharsetUtf8AndEncodeClientCredentialsTrueThenConvertsWithUrlEncoding() {
		this.converter = DefaultOAuth2TokenRequestHeadersConverter.withCharsetUtf8();
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials()
				.clientId("clientId")
				.clientSecret("clientSecret=")
				.build();
		// @formatter:on
		OAuth2ClientCredentialsGrantRequest grantRequest = new OAuth2ClientCredentialsGrantRequest(clientRegistration);
		HttpHeaders defaultHeaders = this.converter.convert(grantRequest);
		assertThat(defaultHeaders.getAccept()).containsExactly(APPLICATION_JSON_UTF8);
		assertThat(defaultHeaders.getContentType()).isEqualTo(APPLICATION_FORM_URLENCODED_UTF8);
		assertThat(defaultHeaders.getFirst(HttpHeaders.AUTHORIZATION))
			.isEqualTo("Basic Y2xpZW50SWQ6Y2xpZW50U2VjcmV0JTNE");
	}

	@Test
	public void convertWhenWithCharsetUtf8EncodeClientCredentialsFalseThenConvertsWithoutUrlEncoding() {
		this.converter = DefaultOAuth2TokenRequestHeadersConverter.withCharsetUtf8();
		this.converter.setEncodeClientCredentials(false);
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientCredentials()
				.clientId("clientId")
				.clientSecret("clientSecret=")
				.build();
		// @formatter:on
		OAuth2ClientCredentialsGrantRequest grantRequest = new OAuth2ClientCredentialsGrantRequest(clientRegistration);
		HttpHeaders defaultHeaders = this.converter.convert(grantRequest);
		assertThat(defaultHeaders.getAccept()).containsExactly(APPLICATION_JSON_UTF8);
		assertThat(defaultHeaders.getContentType()).isEqualTo(APPLICATION_FORM_URLENCODED_UTF8);
		assertThat(defaultHeaders.getFirst(HttpHeaders.AUTHORIZATION))
			.isEqualTo("Basic Y2xpZW50SWQ6Y2xpZW50U2VjcmV0PQ==");
	}

}
