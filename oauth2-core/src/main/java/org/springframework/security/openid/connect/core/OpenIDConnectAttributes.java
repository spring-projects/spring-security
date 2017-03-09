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
package org.springframework.security.openid.connect.core;

/**
 * @author Joe Grandja
 */
public interface OpenIDConnectAttributes {

	interface Claim {
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
}
