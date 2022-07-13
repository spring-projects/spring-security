/*
 * Copyright 2002-2022 the original author or authors.
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

/**
 * The names of the &quot;Standard Claims&quot; defined by the OpenID Connect Core 1.0
 * specification that can be returned either in the UserInfo Response or the ID Token.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">Standard
 * Claims</a>
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">UserInfo
 * Response</a>
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-core-1_0.html#IDToken">ID Token</a>
 */
public final class StandardClaimNames {

	/**
	 * {@code sub} - the Subject identifier
	 */
	public static final String SUB = "sub";

	/**
	 * {@code name} - the user's full name
	 */
	public static final String NAME = "name";

	/**
	 * {@code given_name} - the user's given name(s) or first name(s)
	 */
	public static final String GIVEN_NAME = "given_name";

	/**
	 * {@code family_name} - the user's surname(s) or last name(s)
	 */
	public static final String FAMILY_NAME = "family_name";

	/**
	 * {@code middle_name} - the user's middle name(s)
	 */
	public static final String MIDDLE_NAME = "middle_name";

	/**
	 * {@code nickname} - the user's nick name that may or may not be the same as the
	 * {@code given_name}
	 */
	public static final String NICKNAME = "nickname";

	/**
	 * {@code preferred_username} - the preferred username that the user wishes to be
	 * referred to
	 */
	public static final String PREFERRED_USERNAME = "preferred_username";

	/**
	 * {@code profile} - the URL of the user's profile page
	 */
	public static final String PROFILE = "profile";

	/**
	 * {@code picture} - the URL of the user's profile picture
	 */
	public static final String PICTURE = "picture";

	/**
	 * {@code website} - the URL of the user's web page or blog
	 */
	public static final String WEBSITE = "website";

	/**
	 * {@code email} - the user's preferred e-mail address
	 */
	public static final String EMAIL = "email";

	/**
	 * {@code email_verified} - {@code true} if the user's e-mail address has been
	 * verified, otherwise {@code false}
	 */
	public static final String EMAIL_VERIFIED = "email_verified";

	/**
	 * {@code gender} - the user's gender
	 */
	public static final String GENDER = "gender";

	/**
	 * {@code birthdate} - the user's birth date
	 */
	public static final String BIRTHDATE = "birthdate";

	/**
	 * {@code zoneinfo} - the user's time zone
	 */
	public static final String ZONEINFO = "zoneinfo";

	/**
	 * {@code locale} - the user's locale
	 */
	public static final String LOCALE = "locale";

	/**
	 * {@code phone_number} - the user's preferred phone number
	 */
	public static final String PHONE_NUMBER = "phone_number";

	/**
	 * {@code phone_number_verified} - {@code true} if the user's phone number has been
	 * verified, otherwise {@code false}
	 */
	public static final String PHONE_NUMBER_VERIFIED = "phone_number_verified";

	/**
	 * {@code address} - the user's preferred postal address
	 */
	public static final String ADDRESS = "address";

	/**
	 * {@code updated_at} - the time the user's information was last updated
	 */
	public static final String UPDATED_AT = "updated_at";

	private StandardClaimNames() {
	}

}
