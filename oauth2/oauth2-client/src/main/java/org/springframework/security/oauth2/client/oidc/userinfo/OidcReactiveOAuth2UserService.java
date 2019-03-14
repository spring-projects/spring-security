/*
 * Copyright 2002-2018 the original author or authors.
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

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import reactor.core.publisher.Mono;

/**
 * An implementation of an {@link ReactiveOAuth2UserService} that supports OpenID Connect 1.0 Provider's.
 *
 * @author Rob Winch
 * @since 5.1
 * @see ReactiveOAuth2UserService
 * @see OidcUserRequest
 * @see OidcUser
 * @see DefaultOidcUser
 * @see OidcUserInfo
 */
public class OidcReactiveOAuth2UserService implements
		ReactiveOAuth2UserService<OidcUserRequest, OidcUser> {

	private static final String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";

	private ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService = new DefaultReactiveOAuth2UserService();

	@Override
	public Mono<OidcUser> loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
		Assert.notNull(userRequest, "userRequest cannot be null");
		return getUserInfo(userRequest)
			.map(userInfo -> new OidcUserAuthority(userRequest.getIdToken(), userInfo))
			.defaultIfEmpty(new OidcUserAuthority(userRequest.getIdToken(), null))
			.map(authority -> {
				OidcUserInfo userInfo = authority.getUserInfo();
				Set<GrantedAuthority> authorities = new HashSet<>();
				authorities.add(authority);
				String userNameAttributeName = userRequest.getClientRegistration()
							.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
				if (StringUtils.hasText(userNameAttributeName)) {
					return new DefaultOidcUser(authorities, userRequest.getIdToken(), userInfo, userNameAttributeName);
				} else {
					return new DefaultOidcUser(authorities, userRequest.getIdToken(), userInfo);
				}
			});
	}

	private Mono<OidcUserInfo> getUserInfo(OidcUserRequest userRequest) {
		if (!OidcUserRequestUtils.shouldRetrieveUserInfo(userRequest)) {
			return Mono.empty();
		}
		return this.oauth2UserService.loadUser(userRequest)
			.map(OAuth2User::getAttributes)
			.map(OidcUserInfo::new)
			.doOnNext(userInfo -> {
				String subject = userInfo.getSubject();
				if (subject == null || !subject.equals(userRequest.getIdToken().getSubject())) {
					OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE);
					throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
				}
			});
	}

	public void setOauth2UserService(ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService) {
		Assert.notNull(oauth2UserService, "oauth2UserService cannot be null");
		this.oauth2UserService = oauth2UserService;
	}
}
