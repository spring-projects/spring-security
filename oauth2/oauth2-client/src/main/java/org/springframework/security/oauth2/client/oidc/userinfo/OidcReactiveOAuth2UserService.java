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

package org.springframework.security.oauth2.client.oidc.userinfo;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;

import reactor.core.publisher.Mono;

import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;

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

	private Function<ClientRegistration, Converter<Map<String, Object>, Map<String, Object>>> claimTypeConverterFactory = (
			clientRegistration) -> DEFAULT_CLAIM_TYPE_CONVERTER;

	private Predicate<OidcUserRequest> retrieveUserInfo = OidcUserRequestUtils::shouldRetrieveUserInfo;

	private BiFunction<OidcUserRequest, OidcUserInfo, Mono<OidcUser>> oidcUserMapper = this::getUser;

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
		return (source) -> ClaimConversionService.getSharedInstance()
			.convert(source, sourceDescriptor, targetDescriptor);
	}

	@Override
	public Mono<OidcUser> loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
		Assert.notNull(userRequest, "userRequest cannot be null");
		// @formatter:off
		return getUserInfo(userRequest)
				.flatMap((userInfo) -> this.oidcUserMapper.apply(userRequest, userInfo))
				.switchIfEmpty(Mono.defer(() -> this.oidcUserMapper.apply(userRequest, null)));
		// @formatter:on
	}

	private Mono<OidcUser> getUser(OidcUserRequest userRequest, OidcUserInfo userInfo) {
		return Mono.just(OidcUserRequestUtils.getUser(userRequest, userInfo));
	}

	private Mono<OidcUserInfo> getUserInfo(OidcUserRequest userRequest) {
		if (!this.retrieveUserInfo.test(userRequest)) {
			return Mono.empty();
		}
		// @formatter:off
		return this.oauth2UserService
				.loadUser(userRequest)
				.map(OAuth2User::getAttributes)
				.map((claims) -> convertClaims(claims, userRequest.getClientRegistration()))
				.map(OidcUserInfo::new)
				.doOnNext((userInfo) -> {
					String subject = userInfo.getSubject();
					if (subject == null || !subject.equals(userRequest.getIdToken().getSubject())) {
						OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE);
						throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
					}
				});
		// @formatter:on
	}

	private Map<String, Object> convertClaims(Map<String, Object> claims, ClientRegistration clientRegistration) {
		Converter<Map<String, Object>, Map<String, Object>> claimTypeConverter = this.claimTypeConverterFactory
			.apply(clientRegistration);
		return (claimTypeConverter != null) ? claimTypeConverter.convert(claims)
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

	/**
	 * Sets the {@code Predicate} used to determine if the UserInfo Endpoint should be
	 * called to retrieve information about the End-User (Resource Owner).
	 * <p>
	 * By default, the UserInfo Endpoint is called if all of the following are true:
	 * <ul>
	 * <li>The user info endpoint is defined on the ClientRegistration</li>
	 * <li>The Client Registration uses the
	 * {@link AuthorizationGrantType#AUTHORIZATION_CODE} and scopes in the access token
	 * are defined in the {@link ClientRegistration}</li>
	 * </ul>
	 * @param retrieveUserInfo the function used to determine if the UserInfo Endpoint
	 * should be called
	 * @since 6.3
	 */
	public final void setRetrieveUserInfo(Predicate<OidcUserRequest> retrieveUserInfo) {
		Assert.notNull(retrieveUserInfo, "retrieveUserInfo cannot be null");
		this.retrieveUserInfo = retrieveUserInfo;
	}

	/**
	 * Sets the {@code BiFunction} used to map the {@link OidcUser user} from the
	 * {@link OidcUserRequest user request} and {@link OidcUserInfo user info}.
	 * <p>
	 * This is useful when you need to map the user or authorities from the access token
	 * itself. For example, when the authorization server provides authorization
	 * information in the access token payload you can do the following: <pre>
	 * 	&#64;Bean
	 * 	public OidcReactiveOAuth2UserService oidcUserService() {
	 * 		var userService = new OidcReactiveOAuth2UserService();
	 * 		userService.setOidcUserMapper(oidcUserMapper());
	 * 		return userService;
	 * 	}
	 *
	 * 	private static BiFunction&lt;OidcUserRequest, OidcUserInfo, Mono&lt;OidcUser&gt;&gt; oidcUserMapper() {
	 * 		return (userRequest, userInfo) -> {
	 * 			var accessToken = userRequest.getAccessToken();
	 * 			var grantedAuthorities = new HashSet&lt;GrantedAuthority&gt;();
	 * 			// TODO: Map authorities from the access token
	 * 			var userNameAttributeName = "preferred_username";
	 * 			return Mono.just(new DefaultOidcUser(
	 * 				grantedAuthorities,
	 * 				userRequest.getIdToken(),
	 * 				userInfo,
	 * 				userNameAttributeName
	 * 			));
	 * 		};
	 * 	}
	 * </pre>
	 * <p>
	 * Note that you can access the {@code userNameAttributeName} via the
	 * {@link ClientRegistration} as follows: <pre>
	 * 	var userNameAttributeName = userRequest.getClientRegistration()
	 * 		.getProviderDetails()
	 * 		.getUserInfoEndpoint()
	 * 		.getUserNameAttributeName();
	 * </pre>
	 * <p>
	 * By default, a {@link DefaultOidcUser} is created with authorities mapped as
	 * follows:
	 * <ul>
	 * <li>An {@link OidcUserAuthority} is created from the {@link OidcIdToken} and
	 * {@link OidcUserInfo} with an authority of {@code OIDC_USER}</li>
	 * <li>Additional {@link SimpleGrantedAuthority authorities} are mapped from the
	 * {@link OAuth2AccessToken#getScopes() access token scopes} with a prefix of
	 * {@code SCOPE_}</li>
	 * </ul>
	 * @param oidcUserMapper the function used to map the {@link OidcUser} from the
	 * {@link OidcUserRequest} and {@link OidcUserInfo}
	 * @since 6.3
	 */
	public final void setOidcUserMapper(BiFunction<OidcUserRequest, OidcUserInfo, Mono<OidcUser>> oidcUserMapper) {
		Assert.notNull(oidcUserMapper, "oidcUserMapper cannot be null");
		this.oidcUserMapper = oidcUserMapper;
	}

}
