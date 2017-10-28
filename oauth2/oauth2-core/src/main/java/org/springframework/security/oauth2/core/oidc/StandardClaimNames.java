/*
 * Copyright 2002-2017 the original author or authors.
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

/**
 * The names of the &quot;Standard Claims&quot; defined by the <i>OpenID Connect Core 1.0</i> specification
 * that can be returned either in the <i>UserInfo Response</i> or the <i>ID Token</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">Standard Claims</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">UserInfo Response</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#IDToken">ID Token</a>
 */
public interface StandardClaimNames {

	String SUB = "sub";

	String NAME = "name";

	String GIVEN_NAME = "given_name";

	String FAMILY_NAME = "family_name";

	String MIDDLE_NAME = "middle_name";

	String NICKNAME = "nickname";

	String PREFERRED_USERNAME = "preferred_username";

	String PROFILE = "profile";

	String PICTURE = "picture";

	String WEBSITE = "website";

	String EMAIL = "email";

	String EMAIL_VERIFIED = "email_verified";

	String GENDER = "gender";

	String BIRTHDATE = "birthdate";

	String ZONEINFO = "zoneinfo";

	String LOCALE = "locale";

	String PHONE_NUMBER = "phone_number";

	String PHONE_NUMBER_VERIFIED = "phone_number_verified";

	String ADDRESS = "address";

	String UPDATED_AT = "updated_at";

}
