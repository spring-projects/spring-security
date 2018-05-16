/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.userinfo;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.util.StringUtils;
import org.springframework.web.client.ResponseExtractor;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Created by XYUU <xyuu@xyuu.net> on 2018/5/16.
 */
public class OidcUserExtractor implements DefaultOAuth2UserService.OAuth2UserExtractor<OidcUserRequest, OidcUser>,
		ApplicationContextAware {
	public static final String NAME = "oidc";
	private static final String OAUTH2_OBJECTMAPPER_BEAN_NAME = "oauth2ObjectMapper";
	private final Set<String> userInfoScopes = new HashSet<>(
			Arrays.asList(OidcScopes.PROFILE, OidcScopes.EMAIL, OidcScopes.ADDRESS, OidcScopes.PHONE));
	private final static String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";
	private final TypeReference<Map<String, Object>> typeReference = new TypeReference<Map<String, Object>>() {
	};
	private ObjectMapper objectMapper;

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.objectMapper = applicationContext.containsBean(OAUTH2_OBJECTMAPPER_BEAN_NAME) ?
				applicationContext.getBean(OAUTH2_OBJECTMAPPER_BEAN_NAME, ObjectMapper.class) :
				Jackson2ObjectMapperBuilder.json().build();
	}

	@Override
	public ResponseExtractor<OidcUser> apply(OidcUserRequest userRequest) {
		return response -> {
			OidcUserInfo userInfo = null;
			if (this.shouldRetrieveUserInfo(userRequest)) {
				Map<String, Object> userAttributes = objectMapper.readValue(response.getBody(), typeReference);
				userInfo = new OidcUserInfo(userAttributes);
				// http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
				// Due to the possibility of token substitution attacks (see Section 16.11),
				// the UserInfo Response is not guaranteed to be about the End-User
				// identified by the sub (subject) element of the ID Token.
				// The sub Claim in the UserInfo Response MUST be verified to exactly match
				// the sub Claim in the ID Token; if they do not match,
				// the UserInfo Response values MUST NOT be used.
				if (!userInfo.getSubject().equals(userRequest.getIdToken().getSubject())) {
					OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE);
					throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
				}
			}

			GrantedAuthority authority = new OidcUserAuthority(userRequest.getIdToken(), userInfo);
			Set<GrantedAuthority> authorities = new HashSet<>();
			authorities.add(authority);

			OidcUser user;

			String userNameAttributeName = userRequest.getClientRegistration()
					.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
			if (StringUtils.hasText(userNameAttributeName)) {
				user = new DefaultOidcUser(authorities, userRequest.getIdToken(), userInfo, userNameAttributeName);
			} else {
				user = new DefaultOidcUser(authorities, userRequest.getIdToken(), userInfo);
			}
			return user;
		};
	}

	private boolean shouldRetrieveUserInfo(OidcUserRequest userRequest) {
		// Auto-disabled if UserInfo Endpoint URI is not provided
		if (StringUtils.isEmpty(userRequest.getClientRegistration().getProviderDetails()
				.getUserInfoEndpoint().getUri())) {
			return false;
		}
		// The Claims requested by the profile, email, address, and phone scope values
		// are returned from the UserInfo Endpoint (as described in Section 5.3.2),
		// when a response_type value is used that results in an Access Token being issued.
		// However, when no Access Token is issued, which is the case for the response_type=id_token,
		// the resulting Claims are returned in the ID Token.
		// The Authorization Code Grant Flow, which is response_type=code, results in an Access Token being issued.
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(
				userRequest.getClientRegistration().getAuthorizationGrantType())) {

			// Return true if there is at least one match between the authorized scope(s) and UserInfo scope(s)
			return userRequest.getAccessToken().getScopes().stream().anyMatch(userInfoScopes::contains);
		}
		return false;
	}

}
