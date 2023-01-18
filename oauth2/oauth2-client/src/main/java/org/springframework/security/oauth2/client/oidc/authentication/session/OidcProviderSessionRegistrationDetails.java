/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.authentication.session;

import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.csrf.CsrfToken;

/**
 * A registration of the OIDC Provider Session with the Client's session
 *
 * @author Josh Cummings
 * @since 6.1
 */
public interface OidcProviderSessionRegistrationDetails {

	/**
	 * The Client's session id, typically the browser {@code JSESSIONID}
	 * @return the client session id
	 */
	String getClientSessionId();

	/**
	 * The Client's CSRF Token tied to the client's session
	 * @return the {@link CsrfToken}
	 */
	CsrfToken getCsrfToken();

	/**
	 * The Provider's End User, including any indicated session id
	 * @return
	 */
	OidcUser getPrincipal();

}
