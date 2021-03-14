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

import org.junit.Before;
import org.junit.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.util.MultiValueMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2JwtBearerGrantRequestEntityConverter}.
 *
 * @author Hassene Laaribi
 */
public class OAuth2JwtBearerGrantRequestEntityConverterTests {

	private static final String UTF_8_CHARSET = ";charset=UTF-8";

	private final OAuth2JwtBearerGrantRequestEntityConverter converter = new OAuth2JwtBearerGrantRequestEntityConverter();

	private OAuth2JwtBearerGrantRequest jwtBearerGrantRequest;

	private final Jwt jwtBearerToken = TestJwts.jwt().build();

	@Before
	public void setup() {
		// @formatter:off
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
				.authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
				.scope("read", "write")
				.build();
		// @formatter:on
		this.jwtBearerGrantRequest = new OAuth2JwtBearerGrantRequest(clientRegistration, this.jwtBearerToken);
	}

	@Test
	public void convertWhenGrantRequestValidThenConverts() {
		RequestEntity<?> requestEntity = this.converter.convert(this.jwtBearerGrantRequest);
		ClientRegistration clientRegistration = this.jwtBearerGrantRequest.getClientRegistration();
		assertThat(requestEntity.getMethod()).isEqualTo(HttpMethod.POST);
		assertThat(requestEntity.getUrl().toASCIIString())
				.isEqualTo(clientRegistration.getProviderDetails().getTokenUri());
		HttpHeaders headers = requestEntity.getHeaders();
		assertThat(headers.getAccept()).contains(MediaType.valueOf(MediaType.APPLICATION_JSON_VALUE + UTF_8_CHARSET));
		assertThat(headers.getContentType())
				.isEqualTo(MediaType.valueOf(MediaType.APPLICATION_FORM_URLENCODED_VALUE + UTF_8_CHARSET));
		assertThat(headers.getFirst(HttpHeaders.AUTHORIZATION)).startsWith("Basic ");
		MultiValueMap<String, String> formParameters = (MultiValueMap<String, String>) requestEntity.getBody();
		assertThat(formParameters.getFirst(OAuth2ParameterNames.GRANT_TYPE))
				.isEqualTo(AuthorizationGrantType.JWT_BEARER.getValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.ASSERTION))
				.isEqualTo(this.jwtBearerToken.getTokenValue());
		assertThat(formParameters.getFirst(OAuth2ParameterNames.SCOPE)).isEqualTo("read write");
	}

}
