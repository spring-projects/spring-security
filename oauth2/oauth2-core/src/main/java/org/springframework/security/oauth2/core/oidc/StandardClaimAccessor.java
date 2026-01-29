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

package org.springframework.security.oauth2.core.oidc;

import java.time.Instant;
import java.util.Map;

import org.jspecify.annotations.Nullable;

import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.util.CollectionUtils;

/**
 * A {@link ClaimAccessor} for the &quot;Standard Claims&quot; that can be returned either
 * in the UserInfo Response or the ID Token.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see ClaimAccessor
 * @see StandardClaimNames
 * @see OidcUserInfo
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">UserInfo
 * Response</a>
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">Standard
 * Claims</a>
 */
public interface StandardClaimAccessor extends ClaimAccessor {

	/**
	 * Returns the Subject identifier {@code (sub)}, or {@code null} if it does not exist.
	 * @return the Subject identifier, or {@code null} if it does not exist
	 */
	default @Nullable String getSubject() {
		return this.getClaimAsString(StandardClaimNames.SUB);
	}

	/**
	 * Returns the user's full name {@code (name)} in displayable form, or {@code null} if
	 * it does not exist.
	 * @return the user's full name, or {@code null} if it does not exist
	 */
	default @Nullable String getFullName() {
		return this.getClaimAsString(StandardClaimNames.NAME);
	}

	/**
	 * Returns the user's given name(s) or first name(s) {@code (given_name)}, or
	 * {@code null} if it does not exist.
	 * @return the user's given name(s), or {@code null} if it does not exist
	 */
	default @Nullable String getGivenName() {
		return this.getClaimAsString(StandardClaimNames.GIVEN_NAME);
	}

	/**
	 * Returns the user's surname(s) or last name(s) {@code (family_name)}, or
	 * {@code null} if it does not exist.
	 * @return the user's family names(s), or {@code null} if it does not exist
	 */
	default @Nullable String getFamilyName() {
		return this.getClaimAsString(StandardClaimNames.FAMILY_NAME);
	}

	/**
	 * Returns the user's middle name(s) {@code (middle_name)}, or {@code null} if it does
	 * not exist.
	 * @return the user's middle name(s), or {@code null} if it does not exist
	 */
	default @Nullable String getMiddleName() {
		return this.getClaimAsString(StandardClaimNames.MIDDLE_NAME);
	}

	/**
	 * Returns the user's nick name {@code (nickname)} that may or may not be the same as
	 * the {@code (given_name)}, or {@code null} if it does not exist.
	 * @return the user's nick name, or {@code null} if it does not exist
	 */
	default @Nullable String getNickName() {
		return this.getClaimAsString(StandardClaimNames.NICKNAME);
	}

	/**
	 * Returns the preferred username {@code (preferred_username)} that the user wishes to
	 * be referred to, or {@code null} if it does not exist.
	 * @return the user's preferred user name, or {@code null} if it does not exist
	 */
	default @Nullable String getPreferredUsername() {
		return this.getClaimAsString(StandardClaimNames.PREFERRED_USERNAME);
	}

	/**
	 * Returns the URL of the user's profile page {@code (profile)}, or {@code null} if it
	 * does not exist.
	 * @return the URL of the user's profile page, or {@code null} if it does not exist
	 */
	default @Nullable String getProfile() {
		return this.getClaimAsString(StandardClaimNames.PROFILE);
	}

	/**
	 * Returns the URL of the user's profile picture {@code (picture)}, or {@code null} if
	 * it does not exist.
	 * @return the URL of the user's profile picture, or {@code null} if it does not exist
	 */
	default @Nullable String getPicture() {
		return this.getClaimAsString(StandardClaimNames.PICTURE);
	}

	/**
	 * Returns the URL of the user's web page or blog {@code (website)}, or {@code null}
	 * if it does not exist.
	 * @return the URL of the user's web page or blog, or {@code null} if it does not
	 * exist
	 */
	default @Nullable String getWebsite() {
		return this.getClaimAsString(StandardClaimNames.WEBSITE);
	}

	/**
	 * Returns the user's preferred e-mail address {@code (email)}, or {@code null} if it
	 * does not exist.
	 * @return the user's preferred e-mail address, or {@code null} if it does not exist
	 */
	default @Nullable String getEmail() {
		return this.getClaimAsString(StandardClaimNames.EMAIL);
	}

	/**
	 * Returns {@code true} if the user's e-mail address has been verified
	 * {@code (email_verified)}, otherwise {@code false}, or {@code null} if it does not
	 * exist.
	 * @return {@code true} if the user's e-mail address has been verified, otherwise
	 * {@code false}, or {@code null} if it does not exist
	 */
	default @Nullable Boolean getEmailVerified() {
		return this.getClaimAsBoolean(StandardClaimNames.EMAIL_VERIFIED);
	}

	/**
	 * Returns the user's gender {@code (gender)}, or {@code null} if it does not exist.
	 * @return the user's gender, or {@code null} if it does not exist
	 */
	default @Nullable String getGender() {
		return this.getClaimAsString(StandardClaimNames.GENDER);
	}

	/**
	 * Returns the user's birth date {@code (birthdate)}, or {@code null} if it does not
	 * exist.
	 * @return the user's birth date, or {@code null} if it does not exist
	 */
	default @Nullable String getBirthdate() {
		return this.getClaimAsString(StandardClaimNames.BIRTHDATE);
	}

	/**
	 * Returns the user's time zone {@code (zoneinfo)}, or {@code null} if it does not
	 * exist.
	 * @return the user's time zone, or {@code null} if it does not exist
	 */
	default @Nullable String getZoneInfo() {
		return this.getClaimAsString(StandardClaimNames.ZONEINFO);
	}

	/**
	 * Returns the user's locale {@code (locale)}, or {@code null} if it does not exist.
	 * @return the user's locale, or {@code null} if it does not exist
	 */
	default @Nullable String getLocale() {
		return this.getClaimAsString(StandardClaimNames.LOCALE);
	}

	/**
	 * Returns the user's preferred phone number {@code (phone_number)}, or {@code null}
	 * if it does not exist.
	 * @return the user's preferred phone number, or {@code null} if it does not exist
	 */
	default @Nullable String getPhoneNumber() {
		return this.getClaimAsString(StandardClaimNames.PHONE_NUMBER);
	}

	/**
	 * Returns {@code true} if the user's phone number has been verified
	 * {@code (phone_number_verified)}, otherwise {@code false}, or {@code null} if it
	 * does not exist.
	 * @return {@code true} if the user's phone number has been verified, otherwise
	 * {@code false}, or {@code null} if it does not exist
	 */
	default @Nullable Boolean getPhoneNumberVerified() {
		return this.getClaimAsBoolean(StandardClaimNames.PHONE_NUMBER_VERIFIED);
	}

	/**
	 * Returns the user's preferred postal address {@code (address)}.
	 * @return the user's preferred postal address
	 */
	default AddressStandardClaim getAddress() {
		Map<String, Object> addressFields = this.getClaimAsMap(StandardClaimNames.ADDRESS);
		return (!CollectionUtils.isEmpty(addressFields) ? new DefaultAddressStandardClaim.Builder(addressFields).build()
				: new DefaultAddressStandardClaim.Builder().build());
	}

	/**
	 * Returns the time the user's information was last updated {@code (updated_at)}, or
	 * {@code null} if it does not exist.
	 * @return the time the user's information was last updated, or {@code null} if it
	 * does not exist
	 */
	default @Nullable Instant getUpdatedAt() {
		return this.getClaimAsInstant(StandardClaimNames.UPDATED_AT);
	}

}
