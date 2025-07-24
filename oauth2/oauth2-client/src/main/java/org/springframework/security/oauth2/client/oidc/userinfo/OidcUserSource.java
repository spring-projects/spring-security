/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.userinfo;

import org.jspecify.annotations.Nullable;

import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;

/**
 * The source for the converter to
 * {@link org.springframework.security.oauth2.core.oidc.user.OidcUser}.
 *
 * @author Rob Winch
 * @since 7.0
 */
public class OidcUserSource {

	private final OidcUserRequest userRequest;

	private final @Nullable OidcUserInfo userInfo;

	private final @Nullable OAuth2User oauth2User;

	public OidcUserSource(OidcUserRequest userRequest) {
		this(userRequest, null, null);
	}

	public OidcUserSource(OidcUserRequest userRequest, @Nullable OidcUserInfo userInfo,
			@Nullable OAuth2User oauth2User) {
		Assert.notNull(userRequest, "userRequest cannot be null");
		this.userRequest = userRequest;
		this.userInfo = userInfo;
		this.oauth2User = oauth2User;
	}

	public OidcUserRequest getUserRequest() {
		return this.userRequest;
	}

	public @Nullable OidcUserInfo getUserInfo() {
		return this.userInfo;
	}

	public @Nullable OAuth2User getOauth2User() {
		return this.oauth2User;
	}

}
