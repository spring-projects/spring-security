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
package org.springframework.security.oauth2.oidc.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.oidc.StandardClaimName;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.springframework.security.oauth2.oidc.StandardClaimName.*;

/**
 * The default implementation of a {@link UserInfo}.
 *
 * <p>
 * The <i>key</i> used for accessing the &quot;name&quot; of the
 * <code>Principal</code> (user) via {@link #getAttributes()}
 * is {@link StandardClaimName#NAME} or if not available
 * will default to {@link StandardClaimName#SUB}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see UserInfo
 * @see DefaultOAuth2User
 */
public class DefaultUserInfo extends DefaultOAuth2User implements UserInfo {

	public DefaultUserInfo(Map<String, Object> attributes) {
		this(Collections.emptySet(), attributes);
	}

	public DefaultUserInfo(Set<GrantedAuthority> authorities, Map<String, Object> attributes) {
		super(authorities, attributes, SUB);
	}

	@Override
	public String getSubject() {
		return this.getAttributeAsString(SUB);
	}

	@Override
	public String getName() {
		String name = this.getAttributeAsString(NAME);
		return (name != null ? name : super.getName());
	}

	@Override
	public String getGivenName() {
		return this.getAttributeAsString(GIVEN_NAME);
	}

	@Override
	public String getFamilyName() {
		return this.getAttributeAsString(FAMILY_NAME);
	}

	@Override
	public String getMiddleName() {
		return this.getAttributeAsString(MIDDLE_NAME);
	}

	@Override
	public String getNickName() {
		return this.getAttributeAsString(NICKNAME);
	}

	@Override
	public String getPreferredUsername() {
		return this.getAttributeAsString(PREFERRED_USERNAME);
	}

	@Override
	public String getProfile() {
		return this.getAttributeAsString(PROFILE);
	}

	@Override
	public String getPicture() {
		return this.getAttributeAsString(PICTURE);
	}

	@Override
	public String getWebsite() {
		return this.getAttributeAsString(WEBSITE);
	}

	@Override
	public String getEmail() {
		return this.getAttributeAsString(EMAIL);
	}

	@Override
	public Boolean getEmailVerified() {
		return this.getAttributeAsBoolean(EMAIL_VERIFIED);
	}

	@Override
	public String getGender() {
		return this.getAttributeAsString(GENDER);
	}

	@Override
	public String getBirthdate() {
		return this.getAttributeAsString(BIRTHDATE);
	}

	@Override
	public String getZoneInfo() {
		return this.getAttributeAsString(ZONEINFO);
	}

	@Override
	public String getLocale() {
		return this.getAttributeAsString(LOCALE);
	}

	@Override
	public String getPhoneNumber() {
		return this.getAttributeAsString(PHONE_NUMBER);
	}

	@Override
	public Boolean getPhoneNumberVerified() {
		return this.getAttributeAsBoolean(PHONE_NUMBER_VERIFIED);
	}

	@Override
	public Address getAddress() {
		// TODO Impl
		return null;
	}

	@Override
	public Instant getUpdatedAt() {
		return this.getAttributeAsInstant(UPDATED_AT);
	}
}
