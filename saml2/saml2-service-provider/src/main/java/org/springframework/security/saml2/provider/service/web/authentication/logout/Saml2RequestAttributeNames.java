/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

/**
 * Attribute names for coordinating between SAML 2.0 Logout components.
 *
 * For internal use only.
 *
 * @author Josh Cummings
 */

final class Saml2RequestAttributeNames {

	static final String LOGOUT_REQUEST_ID = Saml2RequestAttributeNames.class.getName() + "_LOGOUT_REQUEST_ID";

	private Saml2RequestAttributeNames() {

	}

}
