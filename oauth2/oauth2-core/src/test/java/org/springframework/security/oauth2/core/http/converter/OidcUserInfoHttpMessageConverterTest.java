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

package org.springframework.security.oauth2.core.http.converter;

import org.junit.Before;
import org.junit.Test;

import org.springframework.http.HttpStatus;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OidcUserInfoHttpMessageConverter}.
 *
 * @author Christian Knoop
 */
public class OidcUserInfoHttpMessageConverterTest {

	private OidcUserInfoHttpMessageConverter messageConverter;

	@Before
	public void setup() {
		this.messageConverter = new OidcUserInfoHttpMessageConverter();
	}

	@Test
	public void supportsWhenOidcUserInfoThenTrue() {
		assertThat(this.messageConverter.supports(OidcUserInfo.class)).isTrue();
	}

	@Test
	public void readInternalWhenSuccessfulUserinfoResponseThenReadOidcUserInfo() {
		// @formatter:off
		String tokenResponse = "{\n"
				+ "   \"sub\": \"248289761001\",\n"
				+ "   \"name\": \"Jane Doe\",\n"
				+ "   \"given_name\": \"Jane\",\n"
				+ "   \"family_name\": \"Doe\",\n"
				+ "   \"preferred_username\": \"j.doe\",\n"
				+ "   \"email\": \"janedoe@example.com\",\n"
				+ "   \"picture\": \"https://example.com/janedoe/me.jpg\"\n"
				+ "}";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(tokenResponse.getBytes(), HttpStatus.OK);
		OidcUserInfo oidcUserInfo = this.messageConverter.readInternal(OidcUserInfo.class, response);
		assertThat(oidcUserInfo.getClaims()).containsEntry("sub", "248289761001");
		assertThat(oidcUserInfo.getClaims()).containsEntry("name", "Jane Doe");
		assertThat(oidcUserInfo.getClaims()).containsEntry("given_name", "Jane");
		assertThat(oidcUserInfo.getClaims()).containsEntry("family_name", "Doe");
		assertThat(oidcUserInfo.getClaims()).containsEntry("preferred_username", "j.doe");
		assertThat(oidcUserInfo.getClaims()).containsEntry("email", "janedoe@example.com");
		assertThat(oidcUserInfo.getClaims()).containsEntry("picture", "https://example.com/janedoe/me.jpg");
	}

	@Test
	public void readInternalWhenSuccessfulUserinfoResponseWithNullValueThenReadOAuth2UserAuthority() {
		// @formatter:off
		String tokenResponse = "{\n"
				+ "   \"sub\": \"248289761001\",\n"
				+ "   \"name\": \"Jane Doe\",\n"
				+ "   \"given_name\": \"Jane\",\n"
				+ "   \"family_name\": null,\n" // null value
				+ "   \"preferred_username\": \"j.doe\",\n"
				+ "   \"email\": \"janedoe@example.com\",\n"
				+ "   \"picture\": \"https://example.com/janedoe/me.jpg\"\n"
				+ "}";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(tokenResponse.getBytes(), HttpStatus.OK);
		OidcUserInfo oidcUserInfo = this.messageConverter.readInternal(OidcUserInfo.class, response);
		assertThat(oidcUserInfo.getClaims()).containsEntry("sub", "248289761001");
		assertThat(oidcUserInfo.getClaims()).containsEntry("name", "Jane Doe");
		assertThat(oidcUserInfo.getClaims()).containsEntry("given_name", "Jane");
		assertThat(oidcUserInfo.getClaims()).containsEntry("family_name", null);
		assertThat(oidcUserInfo.getClaims()).containsEntry("preferred_username", "j.doe");
		assertThat(oidcUserInfo.getClaims()).containsEntry("email", "janedoe@example.com");
		assertThat(oidcUserInfo.getClaims()).containsEntry("picture", "https://example.com/janedoe/me.jpg");
	}

}
