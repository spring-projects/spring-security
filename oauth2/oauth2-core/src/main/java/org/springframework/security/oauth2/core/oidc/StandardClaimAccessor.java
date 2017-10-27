/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.core.oidc;

import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.util.CollectionUtils;

import java.time.Instant;
import java.util.Map;

/**
 * A {@link ClaimAccessor} for the &quot;Standard Claims&quot; that can be returned
 * either in the <i>UserInfo Response</i> or the <i>ID Token</i>.
 *
 * @see ClaimAccessor
 * @see StandardClaim
 * @see UserInfo
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">UserInfo Response</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">Standard Claims</a>
 * @author Joe Grandja
 * @since 5.0
 */
public interface StandardClaimAccessor extends ClaimAccessor {

	default String getSubject() {
		return this.getClaimAsString(StandardClaim.SUB);
	}

	default String getFullName() {
		return this.getClaimAsString(StandardClaim.NAME);
	}

	default String getGivenName() {
		return this.getClaimAsString(StandardClaim.GIVEN_NAME);
	}

	default String getFamilyName() {
		return this.getClaimAsString(StandardClaim.FAMILY_NAME);
	}

	default String getMiddleName() {
		return this.getClaimAsString(StandardClaim.MIDDLE_NAME);
	}

	default String getNickName() {
		return this.getClaimAsString(StandardClaim.NICKNAME);
	}

	default String getPreferredUsername() {
		return this.getClaimAsString(StandardClaim.PREFERRED_USERNAME);
	}

	default String getProfile() {
		return this.getClaimAsString(StandardClaim.PROFILE);
	}

	default String getPicture() {
		return this.getClaimAsString(StandardClaim.PICTURE);
	}

	default String getWebsite() {
		return this.getClaimAsString(StandardClaim.WEBSITE);
	}

	default String getEmail() {
		return this.getClaimAsString(StandardClaim.EMAIL);
	}

	default Boolean getEmailVerified() {
		return this.getClaimAsBoolean(StandardClaim.EMAIL_VERIFIED);
	}

	default String getGender() {
		return this.getClaimAsString(StandardClaim.GENDER);
	}

	default String getBirthdate() {
		return this.getClaimAsString(StandardClaim.BIRTHDATE);
	}

	default String getZoneInfo() {
		return this.getClaimAsString(StandardClaim.ZONEINFO);
	}

	default String getLocale() {
		return this.getClaimAsString(StandardClaim.LOCALE);
	}

	default String getPhoneNumber() {
		return this.getClaimAsString(StandardClaim.PHONE_NUMBER);
	}

	default Boolean getPhoneNumberVerified() {
		return this.getClaimAsBoolean(StandardClaim.PHONE_NUMBER_VERIFIED);
	}

	default Address getAddress() {
		Map<String, Object> addressFields = this.getClaimAsMap(StandardClaim.ADDRESS);
		return (!CollectionUtils.isEmpty(addressFields) ?
			new DefaultAddress.Builder(addressFields).build() :
			new DefaultAddress.Builder().build());
	}

	default Instant getUpdatedAt() {
		return this.getClaimAsInstant(StandardClaim.UPDATED_AT);
	}
}
