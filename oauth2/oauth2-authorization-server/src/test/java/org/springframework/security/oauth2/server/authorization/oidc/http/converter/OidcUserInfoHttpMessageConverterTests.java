/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.oidc.http.converter;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.mock.http.MockHttpOutputMessage;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OidcUserInfoHttpMessageConverter}.
 *
 * @author Steve Riesenberg
 */
public class OidcUserInfoHttpMessageConverterTests {

	private final OidcUserInfoHttpMessageConverter messageConverter = new OidcUserInfoHttpMessageConverter();

	@Test
	public void supportsWhenOidcUserInfoThenTrue() {
		assertThat(this.messageConverter.supports(OidcUserInfo.class)).isTrue();
	}

	@Test
	public void setUserInfoConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.messageConverter.setUserInfoConverter(null));
	}

	@Test
	public void setUserInfoParametersConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.messageConverter.setUserInfoParametersConverter(null));
	}

	@Test
	public void readInternalWhenValidParametersThenSuccess() {
		// @formatter:off
		String userInfoResponse = "{\n" +
				"	\"sub\": \"user1\",\n" +
				"	\"name\": \"First Last\",\n" +
				"	\"given_name\": \"First\",\n" +
				"	\"family_name\": \"Last\",\n" +
				"	\"middle_name\": \"Middle\",\n" +
				"	\"nickname\": \"User\",\n" +
				"	\"preferred_username\": \"user\",\n" +
				"	\"profile\": \"https://example.com/user1\",\n" +
				"	\"picture\": \"https://example.com/user1.jpg\",\n" +
				"	\"website\": \"https://example.com\",\n" +
				"	\"email\": \"user1@example.com\",\n" +
				"	\"email_verified\": \"true\",\n" +
				"	\"gender\": \"female\",\n" +
				"	\"birthdate\": \"1970-01-01\",\n" +
				"	\"zoneinfo\": \"Europe/Paris\",\n" +
				"	\"locale\": \"en-US\",\n" +
				"	\"phone_number\": \"+1 (604) 555-1234;ext=5678\",\n" +
				"	\"phone_number_verified\": \"false\",\n" +
				"	\"address\": {\n" +
				"		\"formatted\": \"Champ de Mars\\n5 Av. Anatole France\\n75007 Paris\\nFrance\",\n" +
				"		\"street_address\": \"Champ de Mars\\n5 Av. Anatole France\",\n" +
				"		\"locality\": \"Paris\",\n" +
				"		\"postal_code\": \"75007\",\n" +
				"		\"country\": \"France\"\n" +
				"	},\n" +
				"	\"updated_at\": 1607633867\n" +
				"}\n";
		// @formatter:on

		MockClientHttpResponse response = new MockClientHttpResponse(userInfoResponse.getBytes(), HttpStatus.OK);
		OidcUserInfo oidcUserInfo = this.messageConverter.readInternal(OidcUserInfo.class, response);

		assertThat(oidcUserInfo.getSubject()).isEqualTo("user1");
		assertThat(oidcUserInfo.getFullName()).isEqualTo("First Last");
		assertThat(oidcUserInfo.getGivenName()).isEqualTo("First");
		assertThat(oidcUserInfo.getFamilyName()).isEqualTo("Last");
		assertThat(oidcUserInfo.getMiddleName()).isEqualTo("Middle");
		assertThat(oidcUserInfo.getNickName()).isEqualTo("User");
		assertThat(oidcUserInfo.getPreferredUsername()).isEqualTo("user");
		assertThat(oidcUserInfo.getProfile()).isEqualTo("https://example.com/user1");
		assertThat(oidcUserInfo.getPicture()).isEqualTo("https://example.com/user1.jpg");
		assertThat(oidcUserInfo.getWebsite()).isEqualTo("https://example.com");
		assertThat(oidcUserInfo.getEmail()).isEqualTo("user1@example.com");
		assertThat(oidcUserInfo.getEmailVerified()).isTrue();
		assertThat(oidcUserInfo.getGender()).isEqualTo("female");
		assertThat(oidcUserInfo.getBirthdate()).isEqualTo("1970-01-01");
		assertThat(oidcUserInfo.getZoneInfo()).isEqualTo("Europe/Paris");
		assertThat(oidcUserInfo.getLocale()).isEqualTo("en-US");
		assertThat(oidcUserInfo.getPhoneNumber()).isEqualTo("+1 (604) 555-1234;ext=5678");
		assertThat(oidcUserInfo.getPhoneNumberVerified()).isFalse();
		assertThat(oidcUserInfo.getAddress().getFormatted())
			.isEqualTo("Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance");
		assertThat(oidcUserInfo.getAddress().getStreetAddress()).isEqualTo("Champ de Mars\n5 Av. Anatole France");
		assertThat(oidcUserInfo.getAddress().getLocality()).isEqualTo("Paris");
		assertThat(oidcUserInfo.getAddress().getPostalCode()).isEqualTo("75007");
		assertThat(oidcUserInfo.getAddress().getCountry()).isEqualTo("France");
		assertThat(oidcUserInfo.getUpdatedAt()).isEqualTo(Instant.ofEpochSecond(1607633867));
	}

	@Test
	public void readInternalWhenFailingConverterThenThrowException() {
		String errorMessage = "this is not a valid converter";
		this.messageConverter.setUserInfoConverter((source) -> {
			throw new RuntimeException(errorMessage);
		});
		MockClientHttpResponse response = new MockClientHttpResponse("{}".getBytes(), HttpStatus.OK);

		assertThatExceptionOfType(HttpMessageNotReadableException.class)
			.isThrownBy(() -> this.messageConverter.readInternal(OidcUserInfo.class, response))
			.withMessageContaining("An error occurred reading the UserInfo response")
			.withMessageContaining(errorMessage);
	}

	@Test
	public void readInternalWhenInvalidResponseThenThrowException() {
		String userInfoResponse = "{}";
		MockClientHttpResponse response = new MockClientHttpResponse(userInfoResponse.getBytes(), HttpStatus.OK);

		assertThatExceptionOfType(HttpMessageNotReadableException.class)
			.isThrownBy(() -> this.messageConverter.readInternal(OidcUserInfo.class, response))
			.withMessageContaining("An error occurred reading the UserInfo response")
			.withMessageContaining("claims cannot be empty");
	}

	@Test
	public void writeInternalWhenOidcUserInfoThenSuccess() {
		OidcUserInfo userInfo = createUserInfo();
		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();

		this.messageConverter.writeInternal(userInfo, outputMessage);

		String userInfoResponse = outputMessage.getBodyAsString();
		assertThat(userInfoResponse).contains("\"sub\":\"user1\"");
		assertThat(userInfoResponse).contains("\"name\":\"First Last\"");
		assertThat(userInfoResponse).contains("\"given_name\":\"First\"");
		assertThat(userInfoResponse).contains("\"family_name\":\"Last\"");
		assertThat(userInfoResponse).contains("\"middle_name\":\"Middle\"");
		assertThat(userInfoResponse).contains("\"nickname\":\"User\"");
		assertThat(userInfoResponse).contains("\"preferred_username\":\"user\"");
		assertThat(userInfoResponse).contains("\"profile\":\"https://example.com/user1\"");
		assertThat(userInfoResponse).contains("\"picture\":\"https://example.com/user1.jpg\"");
		assertThat(userInfoResponse).contains("\"website\":\"https://example.com\"");
		assertThat(userInfoResponse).contains("\"email\":\"user1@example.com\"");
		assertThat(userInfoResponse).contains("\"email_verified\":true");
		assertThat(userInfoResponse).contains("\"gender\":\"female\"");
		assertThat(userInfoResponse).contains("\"birthdate\":\"1970-01-01\"");
		assertThat(userInfoResponse).contains("\"zoneinfo\":\"Europe/Paris\"");
		assertThat(userInfoResponse).contains("\"locale\":\"en-US\"");
		assertThat(userInfoResponse).contains("\"phone_number\":\"+1 (604) 555-1234;ext=5678\"");
		assertThat(userInfoResponse).contains("\"phone_number_verified\":false");
		assertThat(userInfoResponse).contains("\"address\":");
		assertThat(userInfoResponse)
			.contains("\"formatted\":\"Champ de Mars\\n5 Av. Anatole France\\n75007 Paris\\nFrance\"");
		assertThat(userInfoResponse).contains("\"updated_at\":1607633867");
		assertThat(userInfoResponse).contains("\"custom_claim\":\"value\"");
		assertThat(userInfoResponse).contains("\"custom_collection_claim\":[\"value1\",\"value2\"]");
	}

	@Test
	public void writeInternalWhenWriteFailsThenThrowsException() {
		String errorMessage = "this is not a valid converter";
		Converter<OidcUserInfo, Map<String, Object>> failingConverter = (source) -> {
			throw new RuntimeException(errorMessage);
		};
		this.messageConverter.setUserInfoParametersConverter(failingConverter);

		OidcUserInfo userInfo = createUserInfo();
		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();

		assertThatExceptionOfType(HttpMessageNotWritableException.class)
			.isThrownBy(() -> this.messageConverter.writeInternal(userInfo, outputMessage))
			.withMessageContaining("An error occurred writing the UserInfo response")
			.withMessageContaining(errorMessage);
	}

	private static OidcUserInfo createUserInfo() {
		return OidcUserInfo.builder()
			.subject("user1")
			.name("First Last")
			.givenName("First")
			.familyName("Last")
			.middleName("Middle")
			.nickname("User")
			.preferredUsername("user")
			.profile("https://example.com/user1")
			.picture("https://example.com/user1.jpg")
			.website("https://example.com")
			.email("user1@example.com")
			.emailVerified(true)
			.gender("female")
			.birthdate("1970-01-01")
			.zoneinfo("Europe/Paris")
			.locale("en-US")
			.phoneNumber("+1 (604) 555-1234;ext=5678")
			.claim("phone_number_verified", false)
			.claim("address",
					Collections.singletonMap("formatted", "Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance"))
			.claim(StandardClaimNames.UPDATED_AT, Instant.ofEpochSecond(1607633867))
			.claim("custom_claim", "value")
			.claim("custom_collection_claim", Arrays.asList("value1", "value2"))
			.build();
	}

}
