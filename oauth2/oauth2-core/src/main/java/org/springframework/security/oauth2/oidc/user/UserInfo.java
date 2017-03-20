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

import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.time.Instant;

/**
 * A representation of a user <code>Principal</code>
 * that is registered with an <i>OpenID Connect 1.0 Provider</i>.
 *
 * <p>
 * The structure of the user <code>Principal</code> is defined by the
 * <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#UserInfo">UserInfo Endpoint</a>,
 * which is an <i>OAuth 2.0 Protected Resource</i> that returns a set of
 * <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">Claims</a>
 * about the authenticated End-User.
 *
 * <p>
 * Implementation instances of this interface represent an {@link AuthenticatedPrincipal}
 * which is associated to an {@link Authentication} object
 * and may be accessed via {@link Authentication#getPrincipal()}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see DefaultUserInfo
 * @see AuthenticatedPrincipal
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#UserInfo">UserInfo Endpoint</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">Standard Claims</a>
 */
public interface UserInfo extends OAuth2User {

	String getSubject();

	String getGivenName();

	String getFamilyName();

	String getMiddleName();

	String getNickName();

	String getPreferredUsername();

	String getProfile();

	String getPicture();

	String getWebsite();

	String getEmail();

	Boolean getEmailVerified();

	String getGender();

	String getBirthdate();

	String getZoneInfo();

	String getLocale();

	String getPhoneNumber();

	Boolean getPhoneNumberVerified();

	Address getAddress();

	Instant getUpdatedAt();


	interface Address {

		String getFormatted();

		String getStreetAddress();

		String getLocality();

		String getRegion();

		String getPostalCode();

		String getCountry();
	}
}
