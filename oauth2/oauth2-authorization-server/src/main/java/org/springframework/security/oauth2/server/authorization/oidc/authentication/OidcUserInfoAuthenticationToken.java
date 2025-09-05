/*
 * Copyright 2020-2025 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.oidc.authentication;

import java.io.Serial;
import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation used for OpenID Connect 1.0 UserInfo Endpoint.
 *
 * @author Steve Riesenberg
 * @since 0.2.1
 * @see AbstractAuthenticationToken
 * @see OidcUserInfo
 * @see OidcUserInfoAuthenticationProvider
 */
public class OidcUserInfoAuthenticationToken extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = -3463488286180103730L;

	private final Authentication principal;

	private final OidcUserInfo userInfo;

	/**
	 * Constructs an {@code OidcUserInfoAuthenticationToken} using the provided
	 * parameters.
	 * @param principal the principal
	 */
	public OidcUserInfoAuthenticationToken(Authentication principal) {
		super(Collections.emptyList());
		Assert.notNull(principal, "principal cannot be null");
		this.principal = principal;
		this.userInfo = null;
		setAuthenticated(false);
	}

	/**
	 * Constructs an {@code OidcUserInfoAuthenticationToken} using the provided
	 * parameters.
	 * @param principal the authenticated principal
	 * @param userInfo the UserInfo claims
	 */
	public OidcUserInfoAuthenticationToken(Authentication principal, OidcUserInfo userInfo) {
		super(Collections.emptyList());
		Assert.notNull(principal, "principal cannot be null");
		Assert.notNull(userInfo, "userInfo cannot be null");
		this.principal = principal;
		this.userInfo = userInfo;
		setAuthenticated(true);
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	/**
	 * Returns the UserInfo claims.
	 * @return the UserInfo claims
	 */
	public OidcUserInfo getUserInfo() {
		return this.userInfo;
	}

}
