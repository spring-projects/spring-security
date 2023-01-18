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

package org.springframework.security.web.authentication.logout;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.util.Assert;

public class BackchannelLogoutAuthentication extends AbstractAuthenticationToken {

	private final String sessionId;

	private final CsrfToken csrfToken;

	public BackchannelLogoutAuthentication(String sessionId, CsrfToken csrfToken) {
		super(AuthorityUtils.createAuthorityList("BACKCHANNEL_LOGOUT"));
		Assert.notNull(sessionId, "sessionId cannot be null");
		this.sessionId = sessionId;
		this.csrfToken = csrfToken;
	}

	@Override
	public String getPrincipal() {
		return this.sessionId;
	}

	public String getSessionId() {
		return this.sessionId;
	}

	@Override
	public CsrfToken getCredentials() {
		return this.csrfToken;
	}

	public CsrfToken getCsrfToken() {
		return this.csrfToken;
	}

}
