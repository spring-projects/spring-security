/*
 * Copyright 2004-present the original author or authors.
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
import java.util.function.Function;
import java.util.function.Predicate;

import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link OAuth2UserService} that supports OpenID Connect 1.0
 * Provider's.
 *
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @since 5.0
 * @see OAuth2UserService
 * @see OidcUserRequest
 * @see OidcUser
 * @see DefaultOidcUser
 * @see OidcUserInfo
 */
public class OidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

	private static final String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";

	private static final Converter<Map<String, Object>, Map<String, Object>> DEFAULT_CLAIM_TYPE_CONVERTER = new ClaimTypeConverter(
			createDefaultClaimTypeConverters());

	private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService = new DefaultOAuth2UserService();

	private Function<ClientRegistration, Converter<Map<String, Object>, Map<String, Object>>> claimTypeConverterFactory = (
			clientRegistration) -> DEFAULT_CLAIM_TYPE_CONVERTER;

	private Predicate<OidcUserRequest> retrieveUserInfo = OidcUserRequestUtils::shouldRetrieveUserInfo;

	private Converter<OidcUserSource, OidcUser> oidcUserConverter = OidcUserRequestUtils::getUser;

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
		TypeDescriptor sourceDescriptor = TypeDescriptor.valueOf(Object.class);
		return (source) -> ClaimConversionService.getSharedInstance()
			.convert(source, sourceDescriptor, targetDescriptor);
	}

	@Override
	public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
		Assert.notNull(userRequest, "userRequest cannot be null");
		OidcUserInfo userInfo = null;
		OAuth2User oauth2User = null;
		if (this.retrieveUserInfo.test(userRequest)) {
			oauth2User = this.oauth2UserService.loadUser(userRequest);
			Map<String, Object> claims = getClaims(userRequest, oauth2User);
			userInfo = new OidcUserInfo(claims);
			// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
			// 1) The sub (subject) Claim MUST always be returned in the UserInfo Response
			if (userInfo.getSubject() == null) {
				OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}
			// 2) Due to the possibility of token substitution attacks (see Section
			// 16.11),
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
		OidcUserSource source = new OidcUserSource(userRequest, userInfo, oauth2User);
		return this.oidcUserConverter.convert(source);
	}

	private Map<String, Object> getClaims(OidcUserRequest userRequest, OAuth2User oauth2User) {
		Converter<Map<String, Object>, Map<String, Object>> converter = this.claimTypeConverterFactory
			.apply(userRequest.getClientRegistration());
		if (converter != null) {
			return converter.convert(oauth2User.getAttributes());
		}
		return DEFAULT_CLAIM_TYPE_CONVERTER.convert(oauth2User.getAttributes());
	}

	/**
	 * Sets the {@link OAuth2UserService} used when requesting the user info resource.
	 * @param oauth2UserService the {@link OAuth2UserService} used when requesting the
	 * user info resource.
	 * @since 5.1
	 */
	public final void setOauth2UserService(OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService) {
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
	 * By default, the UserInfo Endpoint is called if all the following are true:
	 * <ul>
	 * <li>The user info endpoint is defined on the ClientRegistration</li>
	 * <li>The Client Registration uses the
	 * {@link AuthorizationGrantType#AUTHORIZATION_CODE}</li>
	 * </ul>
	 * @param retrieveUserInfo the {@code Predicate} used to determine if the UserInfo
	 * Endpoint should be called
	 * @since 6.3
	 */
	public final void setRetrieveUserInfo(Predicate<OidcUserRequest> retrieveUserInfo) {
		Assert.notNull(retrieveUserInfo, "retrieveUserInfo cannot be null");
		this.retrieveUserInfo = retrieveUserInfo;
	}

	/**
	 * Allows converting from the {@link OidcUserSource} to and {@link OidcUser}.
	 * @param oidcUserConverter the {@link Converter} to use. Cannot be null.
	 */
	public void setOidcUserConverter(Converter<OidcUserSource, OidcUser> oidcUserConverter) {
		Assert.notNull(oidcUserConverter, "oidcUserConverter cannot be null");
		this.oidcUserConverter = oidcUserConverter;
	}

}
