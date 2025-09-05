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

package org.springframework.security.oauth2.server.authorization.authentication;

/**
 * The values defined for the "prompt" parameter for the OpenID Connect 1.0 Authentication
 * Request.
 *
 * @author Joe Grandja
 * @since 1.5
 */
final class OidcPrompt {

	static final String NONE = "none";

	static final String LOGIN = "login";

	static final String CONSENT = "consent";

	static final String SELECT_ACCOUNT = "select_account";

	private OidcPrompt() {
	}

}
