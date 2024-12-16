/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.session;

import java.io.Serial;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * A {@link SessionInformation} extension that enforces the principal be of type
 * {@link OidcUser}.
 *
 * @author Josh Cummings
 * @since 6.2
 */
public class OidcSessionInformation extends SessionInformation {

	@Serial
	private static final long serialVersionUID = -1703808683027974918L;

	private final Map<String, String> authorities;

	/**
	 * Construct an {@link OidcSessionInformation}
	 * @param sessionId the Client's session id
	 * @param authorities any material that authorizes operating on the session
	 * @param user the OIDC Provider's session and end user
	 */
	public OidcSessionInformation(String sessionId, Map<String, String> authorities, OidcUser user) {
		super(user, sessionId, new Date());
		this.authorities = (authorities != null) ? new LinkedHashMap<>(authorities) : Collections.emptyMap();
	}

	/**
	 * Any material needed to authorize operations on this session
	 * @return the {@link Map} of credentials
	 */
	public Map<String, String> getAuthorities() {
		return this.authorities;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public OidcUser getPrincipal() {
		return (OidcUser) super.getPrincipal();
	}

	/**
	 * Copy this {@link OidcSessionInformation}, using a new session identifier
	 * @param sessionId the new session identifier to use
	 * @return a new {@link OidcSessionInformation} instance
	 */
	public OidcSessionInformation withSessionId(String sessionId) {
		return new OidcSessionInformation(sessionId, getAuthorities(), getPrincipal());
	}

}
