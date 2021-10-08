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

import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link OidcUserInfoHttpMessageConverter}.
 *
 * @author Christian Knoop
 */
public class OidcUserInfoHttpMessageConverterTest {

	private OidcUserInfoHttpMessageConverter messageConverter;

	@BeforeEach
	public void setup() {
		this.messageConverter = new OidcUserInfoHttpMessageConverter();
	}

	@Test
	public void setUserInfoResponseConverterWhenNullThenIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.messageConverter.setUserInfoResponseConverter(null))
				.withMessage("userInfoResponseConverter cannot be null");
		// @formatter:on
	}

	@Test
	public void setUserInfoResponseParametersConverterWhenNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.messageConverter.setUserInfoResponseParametersConverter(null))
				.withMessage("userInfoResponseParametersConverter cannot be null");
	}

	@Test
	public void supportsWhenOidcUserInfoThenTrue() {
		assertThat(this.messageConverter.supports(OidcUserInfo.class)).isTrue();
	}

	@Test
	public void readInternalWhenSuccessfulUserInfoResponseThenReadOidcUserInfo() {
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
	public void readInternalWhenSuccessfulUserInfoResponseWithNullValueThenSuccess() {
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

	@Test
	@SuppressWarnings("unchecked")
	public void readInternalWhenUserInfoResponseConverterSetThenCalled() {
		// @formatter:off
		String tokenResponse = "{\n"
				+ "   \"sub\": \"248289761001\"\n"
				+ "}";
		// @formatter:on
		Converter<Map<String, Object>, OidcUserInfo> converter = mock(Converter.class);
		this.messageConverter.setUserInfoResponseConverter(converter);
		MockClientHttpResponse response = new MockClientHttpResponse(tokenResponse.getBytes(), HttpStatus.OK);
		this.messageConverter.readInternal(OidcUserInfo.class, response);
		verify(converter).convert(any());
	}

	@Test
	public void writeInternalWhenOidcUserInfoThenWriteUserInfoResponse() {
		// @formatter:off
		OidcUserInfo userInfo = OidcUserInfo.builder()
				.subject("248289761001")
				.name("Jane Doe")
				.givenName("Jane")
				.familyName("Doe")
				.preferredUsername("j.doe")
				.email("janedoe@example.com")
				.picture("https://example.com/janedoe/me.jpg")
				.build();
		// @formatter:on
		MockClientHttpRequest request = new MockClientHttpRequest();
		this.messageConverter.writeInternal(userInfo, request);
		String body = request.getBodyAsString();
		assertThat(body).contains("\"sub\":\"248289761001\"");
		assertThat(body).contains("\"name\":\"Jane Doe\"");
		assertThat(body).contains("\"given_name\":\"Jane\"");
		assertThat(body).contains("\"family_name\":\"Doe\"");
		assertThat(body).contains("\"preferred_username\":\"j.doe\"");
		assertThat(body).contains("\"email\":\"janedoe@example.com\"");
		assertThat(body).contains("\"picture\":\"https://example.com/janedoe/me.jpg\"");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void writeInternalWhenUserInfoResponseParametersConverterSetThenCalled() {
		// @formatter:off
		OidcUserInfo userInfo = OidcUserInfo.builder()
				.subject("248289761001")
				.build();
		// @formatter:on
		Converter<OidcUserInfo, Map<String, Object>> converter = mock(Converter.class);
		given(converter.convert(any())).willReturn(userInfo.getClaims());
		this.messageConverter.setUserInfoResponseParametersConverter(converter);
		MockClientHttpRequest request = new MockClientHttpRequest();
		this.messageConverter.writeInternal(userInfo, request);
		verify(converter).convert(any());
	}

}
