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

import java.io.Serializable;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.ADDRESS;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.BIRTHDATE;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.EMAIL;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.EMAIL_VERIFIED;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.FAMILY_NAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.GENDER;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.GIVEN_NAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.LOCALE;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.MIDDLE_NAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.NAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.NICKNAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.PHONE_NUMBER;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.PHONE_NUMBER_VERIFIED;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.PICTURE;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.PREFERRED_USERNAME;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.PROFILE;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.SUB;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.UPDATED_AT;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.WEBSITE;
import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.ZONEINFO;

/**
 * A representation of a UserInfo Response that is returned
 * from the OAuth 2.0 Protected Resource UserInfo Endpoint.
 *
 * <p>
 * The {@code OidcUserInfo} contains a set of &quot;Standard Claims&quot; about the authentication of an End-User.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see StandardClaimAccessor
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">UserInfo Response</a>
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">UserInfo Endpoint</a>
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">Standard Claims</a>
 */
public class OidcUserInfo implements StandardClaimAccessor, Serializable {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private final Map<String, Object> claims;

	/**
	 * Constructs a {@code OidcUserInfo} using the provided parameters.
	 *
	 * @param claims the claims about the authentication of the End-User
	 */
	public OidcUserInfo(Map<String, Object> claims) {
		Assert.notEmpty(claims, "claims cannot be empty");
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}

		OidcUserInfo that = (OidcUserInfo) obj;

		return this.getClaims().equals(that.getClaims());
	}

	@Override
	public int hashCode() {
		return this.getClaims().hashCode();
	}

	/**
	 * Create a {@link Builder}
	 *
	 * @return the {@link Builder} for further configuration
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * A builder for {@link OidcUserInfo}s
	 *
	 * @since 5.3
	 * @author Josh Cummings
	 */
	public static final class Builder {
		private final Map<String, Object> claims = new LinkedHashMap<>();

		private Builder() {}

		/**
		 * Use this claim in the resulting {@link OidcUserInfo}
		 *
		 * @param name The claim name
		 * @param value The claim value
		 * @return the {@link Builder} for further configurations
		 */
		public Builder claim(String name, Object value) {
			this.claims.put(name, value);
			return this;
		}

		/**
		 * Provides access to every {@link #claim(String, Object)}
		 * declared so far with the possibility to add, replace, or remove.
		 * @param claimsConsumer the consumer
		 * @return the {@link Builder} for further configurations
		 */
		public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return this;
		}

		/**
		 * Use this address in the resulting {@link OidcUserInfo}
		 *
		 * @param address The address to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder address(String address) {
			return this.claim(ADDRESS, address);
		}

		/**
		 * Use this birthdate in the resulting {@link OidcUserInfo}
		 *
		 * @param birthdate The birthdate to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder birthdate(String birthdate) {
			return this.claim(BIRTHDATE, birthdate);
		}

		/**
		 * Use this email in the resulting {@link OidcUserInfo}
		 *
		 * @param email The email to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder email(String email) {
			return this.claim(EMAIL, email);
		}

		/**
		 * Use this verified-email indicator in the resulting {@link OidcUserInfo}
		 *
		 * @param emailVerified The verified-email indicator to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder emailVerified(Boolean emailVerified) {
			return this.claim(EMAIL_VERIFIED, emailVerified);
		}

		/**
		 * Use this family name in the resulting {@link OidcUserInfo}
		 *
		 * @param familyName The family name to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder familyName(String familyName) {
			return claim(FAMILY_NAME, familyName);
		}

		/**
		 * Use this gender in the resulting {@link OidcUserInfo}
		 *
		 * @param gender The gender to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder gender(String gender) {
			return this.claim(GENDER, gender);
		}

		/**
		 * Use this given name in the resulting {@link OidcUserInfo}
		 *
		 * @param givenName The given name to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder givenName(String givenName) {
			return claim(GIVEN_NAME, givenName);
		}

		/**
		 * Use this locale in the resulting {@link OidcUserInfo}
		 *
		 * @param locale The locale to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder locale(String locale) {
			return this.claim(LOCALE, locale);
		}

		/**
		 * Use this middle name in the resulting {@link OidcUserInfo}
		 *
		 * @param middleName The middle name to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder middleName(String middleName) {
			return claim(MIDDLE_NAME, middleName);
		}

		/**
		 * Use this name in the resulting {@link OidcUserInfo}
		 *
		 * @param name The name to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder name(String name) {
			return claim(NAME, name);
		}

		/**
		 * Use this nickname in the resulting {@link OidcUserInfo}
		 *
		 * @param nickname The nickname to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder nickname(String nickname) {
			return claim(NICKNAME, nickname);
		}

		/**
		 * Use this picture in the resulting {@link OidcUserInfo}
		 *
		 * @param picture The picture to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder picture(String picture) {
			return this.claim(PICTURE, picture);
		}

		/**
		 * Use this phone number in the resulting {@link OidcUserInfo}
		 *
		 * @param phoneNumber The phone number to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder phoneNumber(String phoneNumber) {
			return this.claim(PHONE_NUMBER, phoneNumber);
		}

		/**
		 * Use this verified-phone-number indicator in the resulting {@link OidcUserInfo}
		 *
		 * @param phoneNumberVerified The verified-phone-number indicator to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder phoneNumberVerified(String phoneNumberVerified) {
			return this.claim(PHONE_NUMBER_VERIFIED, phoneNumberVerified);
		}

		/**
		 * Use this preferred username in the resulting {@link OidcUserInfo}
		 *
		 * @param preferredUsername The preferred username to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder preferredUsername(String preferredUsername) {
			return claim(PREFERRED_USERNAME, preferredUsername);
		}

		/**
		 * Use this profile in the resulting {@link OidcUserInfo}
		 *
		 * @param profile The profile to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder profile(String profile) {
			return claim(PROFILE, profile);
		}

		/**
		 * Use this subject in the resulting {@link OidcUserInfo}
		 *
		 * @param subject The subject to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder subject(String subject) {
			return this.claim(SUB, subject);
		}

		/**
		 * Use this updated-at {@link Instant} in the resulting {@link OidcUserInfo}
		 *
		 * @param updatedAt The updated-at {@link Instant} to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder updatedAt(String updatedAt) {
			return this.claim(UPDATED_AT, updatedAt);
		}

		/**
		 * Use this website in the resulting {@link OidcUserInfo}
		 *
		 * @param website The website to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder website(String website) {
			return this.claim(WEBSITE, website);
		}

		/**
		 * Use this zoneinfo in the resulting {@link OidcUserInfo}
		 *
		 * @param zoneinfo The zoneinfo to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder zoneinfo(String zoneinfo) {
			return this.claim(ZONEINFO, zoneinfo);
		}

		/**
		 * Build the {@link OidcUserInfo}
		 *
		 * @return The constructed {@link OidcUserInfo}
		 */
		public OidcUserInfo build() {
			return new OidcUserInfo(this.claims);
		}
	}
}
