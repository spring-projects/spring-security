/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.core.oidc;

import org.junit.Test;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.oauth2.core.oidc.DefaultAddressStandardClaimTests.*;

/**
 * Tests for {@link OidcUserInfo}.
 *
 * @author Joe Grandja
 */
public class OidcUserInfoTests {

	private static final String SUB_CLAIM = "sub";

	private static final String NAME_CLAIM = "name";

	private static final String GIVEN_NAME_CLAIM = "given_name";

	private static final String FAMILY_NAME_CLAIM = "family_name";

	private static final String MIDDLE_NAME_CLAIM = "middle_name";

	private static final String NICKNAME_CLAIM = "nickname";

	private static final String PREFERRED_USERNAME_CLAIM = "preferred_username";

	private static final String PROFILE_CLAIM = "profile";

	private static final String PICTURE_CLAIM = "picture";

	private static final String WEBSITE_CLAIM = "website";

	private static final String EMAIL_CLAIM = "email";

	private static final String EMAIL_VERIFIED_CLAIM = "email_verified";

	private static final String GENDER_CLAIM = "gender";

	private static final String BIRTHDATE_CLAIM = "birthdate";

	private static final String ZONEINFO_CLAIM = "zoneinfo";

	private static final String LOCALE_CLAIM = "locale";

	private static final String PHONE_NUMBER_CLAIM = "phone_number";

	private static final String PHONE_NUMBER_VERIFIED_CLAIM = "phone_number_verified";

	private static final String ADDRESS_CLAIM = "address";

	private static final String UPDATED_AT_CLAIM = "updated_at";

	private static final String SUB_VALUE = "subject1";

	private static final String NAME_VALUE = "full_name";

	private static final String GIVEN_NAME_VALUE = "given_name";

	private static final String FAMILY_NAME_VALUE = "family_name";

	private static final String MIDDLE_NAME_VALUE = "middle_name";

	private static final String NICKNAME_VALUE = "nickname";

	private static final String PREFERRED_USERNAME_VALUE = "preferred_username";

	private static final String PROFILE_VALUE = "profile";

	private static final String PICTURE_VALUE = "picture";

	private static final String WEBSITE_VALUE = "website";

	private static final String EMAIL_VALUE = "email";

	private static final Boolean EMAIL_VERIFIED_VALUE = true;

	private static final String GENDER_VALUE = "gender";

	private static final String BIRTHDATE_VALUE = "birthdate";

	private static final String ZONEINFO_VALUE = "zoneinfo";

	private static final String LOCALE_VALUE = "locale";

	private static final String PHONE_NUMBER_VALUE = "phone_number";

	private static final Boolean PHONE_NUMBER_VERIFIED_VALUE = true;

	private static final Map<String, Object> ADDRESS_VALUE;

	private static final long UPDATED_AT_VALUE = Instant.now().minusSeconds(60).toEpochMilli();

	private static final Map<String, Object> CLAIMS;

	static {
		CLAIMS = new HashMap<>();
		CLAIMS.put(SUB_CLAIM, SUB_VALUE);
		CLAIMS.put(NAME_CLAIM, NAME_VALUE);
		CLAIMS.put(GIVEN_NAME_CLAIM, GIVEN_NAME_VALUE);
		CLAIMS.put(FAMILY_NAME_CLAIM, FAMILY_NAME_VALUE);
		CLAIMS.put(MIDDLE_NAME_CLAIM, MIDDLE_NAME_VALUE);
		CLAIMS.put(NICKNAME_CLAIM, NICKNAME_VALUE);
		CLAIMS.put(PREFERRED_USERNAME_CLAIM, PREFERRED_USERNAME_VALUE);
		CLAIMS.put(PROFILE_CLAIM, PROFILE_VALUE);
		CLAIMS.put(PICTURE_CLAIM, PICTURE_VALUE);
		CLAIMS.put(WEBSITE_CLAIM, WEBSITE_VALUE);
		CLAIMS.put(EMAIL_CLAIM, EMAIL_VALUE);
		CLAIMS.put(EMAIL_VERIFIED_CLAIM, EMAIL_VERIFIED_VALUE);
		CLAIMS.put(GENDER_CLAIM, GENDER_VALUE);
		CLAIMS.put(BIRTHDATE_CLAIM, BIRTHDATE_VALUE);
		CLAIMS.put(ZONEINFO_CLAIM, ZONEINFO_VALUE);
		CLAIMS.put(LOCALE_CLAIM, LOCALE_VALUE);
		CLAIMS.put(PHONE_NUMBER_CLAIM, PHONE_NUMBER_VALUE);
		CLAIMS.put(PHONE_NUMBER_VERIFIED_CLAIM, PHONE_NUMBER_VERIFIED_VALUE);

		ADDRESS_VALUE = new HashMap<>();
		ADDRESS_VALUE.put(FORMATTED_FIELD_NAME, FORMATTED);
		ADDRESS_VALUE.put(STREET_ADDRESS_FIELD_NAME, STREET_ADDRESS);
		ADDRESS_VALUE.put(LOCALITY_FIELD_NAME, LOCALITY);
		ADDRESS_VALUE.put(REGION_FIELD_NAME, REGION);
		ADDRESS_VALUE.put(POSTAL_CODE_FIELD_NAME, POSTAL_CODE);
		ADDRESS_VALUE.put(COUNTRY_FIELD_NAME, COUNTRY);
		CLAIMS.put(ADDRESS_CLAIM, ADDRESS_VALUE);

		CLAIMS.put(UPDATED_AT_CLAIM, UPDATED_AT_VALUE);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenClaimsIsEmptyThenThrowIllegalArgumentException() {
		new OidcUserInfo(Collections.emptyMap());
	}

	@Test
	public void constructorWhenParametersProvidedAndValidThenCreated() {
		OidcUserInfo userInfo = new OidcUserInfo(CLAIMS);

		assertThat(userInfo.getClaims()).isEqualTo(CLAIMS);
		assertThat(userInfo.getSubject()).isEqualTo(SUB_VALUE);
		assertThat(userInfo.getFullName()).isEqualTo(NAME_VALUE);
		assertThat(userInfo.getGivenName()).isEqualTo(GIVEN_NAME_VALUE);
		assertThat(userInfo.getFamilyName()).isEqualTo(FAMILY_NAME_VALUE);
		assertThat(userInfo.getMiddleName()).isEqualTo(MIDDLE_NAME_VALUE);
		assertThat(userInfo.getNickName()).isEqualTo(NICKNAME_VALUE);
		assertThat(userInfo.getPreferredUsername()).isEqualTo(PREFERRED_USERNAME_VALUE);
		assertThat(userInfo.getProfile()).isEqualTo(PROFILE_VALUE);
		assertThat(userInfo.getPicture()).isEqualTo(PICTURE_VALUE);
		assertThat(userInfo.getWebsite()).isEqualTo(WEBSITE_VALUE);
		assertThat(userInfo.getEmail()).isEqualTo(EMAIL_VALUE);
		assertThat(userInfo.getEmailVerified()).isEqualTo(EMAIL_VERIFIED_VALUE);
		assertThat(userInfo.getGender()).isEqualTo(GENDER_VALUE);
		assertThat(userInfo.getBirthdate()).isEqualTo(BIRTHDATE_VALUE);
		assertThat(userInfo.getZoneInfo()).isEqualTo(ZONEINFO_VALUE);
		assertThat(userInfo.getLocale()).isEqualTo(LOCALE_VALUE);
		assertThat(userInfo.getPhoneNumber()).isEqualTo(PHONE_NUMBER_VALUE);
		assertThat(userInfo.getPhoneNumberVerified()).isEqualTo(PHONE_NUMBER_VERIFIED_VALUE);
		assertThat(userInfo.getAddress()).isEqualTo(new DefaultAddressStandardClaim.Builder(ADDRESS_VALUE).build());
		assertThat(userInfo.getUpdatedAt().getEpochSecond()).isEqualTo(UPDATED_AT_VALUE);
	}

}
