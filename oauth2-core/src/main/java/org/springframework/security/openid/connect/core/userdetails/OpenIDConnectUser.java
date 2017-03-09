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
package org.springframework.security.openid.connect.core.userdetails;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.userdetails.OAuth2User;
import org.springframework.security.oauth2.core.userdetails.OAuth2UserAttribute;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.springframework.security.openid.connect.core.OpenIDConnectAttributes.Claim.*;

/**
 * @author Joe Grandja
 */
public class OpenIDConnectUser extends OAuth2User {

	public OpenIDConnectUser(OAuth2UserAttribute identifier, List<OAuth2UserAttribute> attributes) {
		this(identifier, attributes, Collections.emptySet());
	}

	public OpenIDConnectUser(OAuth2UserAttribute identifier, List<OAuth2UserAttribute> attributes, Set<GrantedAuthority> authorities) {
		this(identifier, attributes, authorities, true, true, true, true);
	}


	public OpenIDConnectUser(OAuth2UserAttribute identifier, List<OAuth2UserAttribute> attributes, Set<GrantedAuthority> authorities,
								boolean accountNonExpired, boolean accountNonLocked, boolean credentialsNonExpired, boolean enabled) {

		super(identifier, attributes, authorities, accountNonExpired, accountNonLocked, credentialsNonExpired, enabled);
		this.setUserNameAttributeName(SUB);
	}

	public String getSubject() {
		return this.getAttributeString(SUB);
	}

	public String getName() {
		return this.getAttributeString(NAME);
	}

	public String getGivenName() {
		return this.getAttributeString(GIVEN_NAME);
	}

	public String getFamilyName() {
		return this.getAttributeString(FAMILY_NAME);
	}

	public String getMiddleName() {
		return this.getAttributeString(MIDDLE_NAME);
	}

	public String getNickName() {
		return this.getAttributeString(NICKNAME);
	}

	public String getPreferredUsername() {
		return this.getAttributeString(PREFERRED_USERNAME);
	}

	public String getProfile() {
		return this.getAttributeString(PROFILE);
	}

	public String getPicture() {
		return this.getAttributeString(PICTURE);
	}

	public String getWebsite() {
		return this.getAttributeString(WEBSITE);
	}

	public String getEmail() {
		return this.getAttributeString(EMAIL);
	}

	public boolean getEmailVerified() {
		return this.getAttributeBoolean(EMAIL_VERIFIED);
	}

	public String getGender() {
		return this.getAttributeString(GENDER);
	}

	public String getBirthdate() {
		return this.getAttributeString(BIRTHDATE);
	}

	public String getZoneInfo() {
		return this.getAttributeString(ZONEINFO);
	}

	public String getLocale() {
		return this.getAttributeString(LOCALE);
	}

	public String getPhoneNumber() {
		return this.getAttributeString(PHONE_NUMBER);
	}

	public boolean getPhoneNumberVerified() {
		return this.getAttributeBoolean(PHONE_NUMBER_VERIFIED);
	}

	public String getAddress() {
		return this.getAttributeString(ADDRESS);
	}

	public long getUpdatedAt() {
		return this.getAttributeLong(UPDATED_AT);
	}
}
