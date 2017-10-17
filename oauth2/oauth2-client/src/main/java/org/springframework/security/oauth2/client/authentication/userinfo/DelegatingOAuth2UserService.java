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
package org.springframework.security.oauth2.client.authentication.userinfo;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * An implementation of an {@link OAuth2UserService} that simply delegates
 * to it's internal <code>List</code> of {@link OAuth2UserService}'s.
 * <p>
 * Each {@link OAuth2UserService} is given a chance to
 * {@link OAuth2UserService#loadUser(OAuth2ClientAuthenticationToken) load} an {@link OAuth2User}
 * with the first <code>non-null</code> {@link OAuth2User} being returned.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2UserService
 * @see OAuth2User
 */
public class DelegatingOAuth2UserService implements OAuth2UserService {
	private final List<OAuth2UserService> userServices;

	public DelegatingOAuth2UserService(List<OAuth2UserService> userServices) {
		Assert.notEmpty(userServices, "userServices cannot be empty");
		this.userServices = Collections.unmodifiableList(new ArrayList<>(userServices));
	}

	@Override
	public OAuth2User loadUser(OAuth2ClientAuthenticationToken clientAuthentication) throws OAuth2AuthenticationException {
		OAuth2User oauth2User = this.userServices.stream()
			.map(userService -> userService.loadUser(clientAuthentication))
			.filter(Objects::nonNull)
			.findFirst()
			.orElse(null);
		return oauth2User;
	}
}
