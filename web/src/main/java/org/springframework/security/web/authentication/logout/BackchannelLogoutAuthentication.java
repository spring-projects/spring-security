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

import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.util.Assert;

public class BackchannelLogoutAuthentication extends AbstractAuthenticationToken {

	private final Object principal;

	private final Object credentials;

	private final Iterable<? extends SessionInformation> sessions;

	public BackchannelLogoutAuthentication(Object principal, Object credentials,
			Iterable<? extends SessionInformation> sessions) {
		super(Collections.emptyList());
		Assert.notNull(sessions, "sessions cannot be null");
		this.sessions = sessions;
		this.principal = principal;
		this.credentials = credentials;
		setAuthenticated(true);
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public Object getCredentials() {
		return this.credentials;
	}

	public Iterable<? extends SessionInformation> getSessions() {
		return this.sessions;
	}

}
