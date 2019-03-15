/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.userinfo;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * An implementation of an {@link OAuth2UserService} that simply delegates
 * to it's internal {@code List} of {@link OAuth2UserService}(s).
 * <p>
 * Each {@link OAuth2UserService} is given a chance to
 * {@link OAuth2UserService#loadUser(OAuth2UserRequest) load} an {@link OAuth2User}
 * with the first {@code non-null} {@link OAuth2User} being returned.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2UserService
 * @see OAuth2UserRequest
 * @see OAuth2User
 *
 * @param <R> The type of OAuth 2.0 User Request
 * @param <U> The type of OAuth 2.0 User
 */
public class DelegatingOAuth2UserService<R extends OAuth2UserRequest, U extends OAuth2User> implements OAuth2UserService<R, U> {
	private final List<OAuth2UserService<R, U>> userServices;

	/**
	 * Constructs a {@code DelegatingOAuth2UserService} using the provided parameters.
	 *
	 * @param userServices a {@code List} of {@link OAuth2UserService}(s)
	 */
	public DelegatingOAuth2UserService(List<OAuth2UserService<R, U>> userServices) {
		Assert.notEmpty(userServices, "userServices cannot be empty");
		this.userServices = Collections.unmodifiableList(new ArrayList<>(userServices));
	}

	@Override
	public U loadUser(R userRequest) throws OAuth2AuthenticationException {
		Assert.notNull(userRequest, "userRequest cannot be null");
		return this.userServices.stream()
			.map(userService -> userService.loadUser(userRequest))
			.filter(Objects::nonNull)
			.findFirst()
			.orElse(null);
	}
}
