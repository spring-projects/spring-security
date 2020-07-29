/*
 * Copyright 2002-2019 the original author or authors.
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

import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import reactor.core.publisher.Mono;

import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An implementation of an {@link ReactiveOAuth2UserService} that supports OpenID Connect
 * 1.0 Provider's.
 *
 * @author Rob Winch
 * @since 5.1
 * @see ReactiveOAuth2UserService
 * @see OidcUserRequest
 * @see OidcUser
 * @see DefaultOidcUser
 * @see OidcUserInfo
 */
public class OidcReactiveOAuth2UserService implements ReactiveOAuth2UserService<OidcUserRequest, OidcUser> {

	private static final String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";

	private static final Converter<Map<String, Object>, Map<String, Object>> DEFAULT_CLAIM_TYPE_CONVERTER = new ClaimTypeConverter(
			createDefaultClaimTypeConverters());

	private ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService = new DefaultReactiveOAuth2UserService();

	private Function<ClientRegistration, Converter<Map<String, Object>, Map<String, Object>>> claimTypeConverterFactory = clientRegistration -> DEFAULT_CLAIM_TYPE_CONVERTER;

	/**
	 * Returns the default {@link Converter}'s used for type conversion of claim values
	 * for an {@link OidcUserInfo}.
	 * @return a {@link Map} of {@link Converter}'s keyed by {@link StandardClaimNames
	 * claim name}
	 * @since 5.2
	 */
	public static Map<String, Converter<Object, ?>> createDefaultClaimTypeConverters() {
		Converter<Object, ?> booleanConverter = getConverter(TypeDescriptor.valueOf(Boolean.class));
		Converter<Object, ?> instantConverter = getConverter(TypeDescriptor.valueOf(Instant.class));

		Map<String, Converter<Object, ?>> claimTypeConverters = new HashMap<>();
		claimTypeConverters.put(StandardClaimNames.EMAIL_VERIFIED, booleanConverter);
		claimTypeConverters.put(StandardClaimNames.PHONE_NUMBER_VERIFIED, booleanConverter);
		claimTypeConverters.put(StandardClaimNames.UPDATED_AT, instantConverter);
		return claimTypeConverters;
	}

	private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
		final TypeDescriptor sourceDescriptor = TypeDescriptor.valueOf(Object.class);
		return source -> ClaimConversionService.getSharedInstance().convert(source, sourceDescriptor, targetDescriptor);
	}

	@Override
	public Mono<OidcUser> loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
		Assert.notNull(userRequest, "userRequest cannot be null");
		return getUserInfo(userRequest).map(userInfo -> new OidcUserAuthority(userRequest.getIdToken(), userInfo))
				.defaultIfEmpty(new OidcUserAuthority(userRequest.getIdToken(), null)).map(authority -> {
					OidcUserInfo userInfo = authority.getUserInfo();
					Set<GrantedAuthority> authorities = new HashSet<>();
					authorities.add(authority);
					OAuth2AccessToken token = userRequest.getAccessToken();
					for (String scope : token.getScopes()) {
						authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
					}
					String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
							.getUserInfoEndpoint().getUserNameAttributeName();
					if (StringUtils.hasText(userNameAttributeName)) {
						return new DefaultOidcUser(authorities, userRequest.getIdToken(), userInfo,
								userNameAttributeName);
					}
					else {
						return new DefaultOidcUser(authorities, userRequest.getIdToken(), userInfo);
					}
				});
	}

	private Mono<OidcUserInfo> getUserInfo(OidcUserRequest userRequest) {
		if (!OidcUserRequestUtils.shouldRetrieveUserInfo(userRequest)) {
			return Mono.empty();
		}

		return this.oauth2UserService.loadUser(userRequest).map(OAuth2User::getAttributes)
				.map(claims -> convertClaims(claims, userRequest.getClientRegistration())).map(OidcUserInfo::new)
				.doOnNext(userInfo -> {
					String subject = userInfo.getSubject();
					if (subject == null || !subject.equals(userRequest.getIdToken().getSubject())) {
						OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE);
						throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
					}
				});
	}

	private Map<String, Object> convertClaims(Map<String, Object> claims, ClientRegistration clientRegistration) {
		Converter<Map<String, Object>, Map<String, Object>> claimTypeConverter = this.claimTypeConverterFactory
				.apply(clientRegistration);
		return claimTypeConverter != null ? claimTypeConverter.convert(claims)
				: DEFAULT_CLAIM_TYPE_CONVERTER.convert(claims);
	}

	public void setOauth2UserService(ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService) {
		Assert.notNull(oauth2UserService, "oauth2UserService cannot be null");
		this.oauth2UserService = oauth2UserService;
	}

	/**
	 * Sets the factory that provides a {@link Converter} used for type conversion of
	 * claim values for an {@link OidcUserInfo}. The default is {@link ClaimTypeConverter}
	 * for all {@link ClientRegistration clients}.
	 * @param claimTypeConverterFactory the factory that provides a {@link Converter} used
	 * for type conversion of claim values for a specific {@link ClientRegistration
	 * client}
	 * @since 5.2
	 */
	public final void setClaimTypeConverterFactory(
			Function<ClientRegistration, Converter<Map<String, Object>, Map<String, Object>>> claimTypeConverterFactory) {
		Assert.notNull(claimTypeConverterFactory, "claimTypeConverterFactory cannot be null");
		this.claimTypeConverterFactory = claimTypeConverterFactory;
	}

}
