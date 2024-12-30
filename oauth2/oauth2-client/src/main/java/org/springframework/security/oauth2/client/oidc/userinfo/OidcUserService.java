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
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;

import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

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

	private Set<String> accessibleScopes = new HashSet<>(
			Arrays.asList(OidcScopes.PROFILE, OidcScopes.EMAIL, OidcScopes.ADDRESS, OidcScopes.PHONE));

	private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService = new DefaultOAuth2UserService();

	private Function<ClientRegistration, Converter<Map<String, Object>, Map<String, Object>>> claimTypeConverterFactory = (
			clientRegistration) -> DEFAULT_CLAIM_TYPE_CONVERTER;

	private Predicate<OidcUserRequest> retrieveUserInfo = this::shouldRetrieveUserInfo;

	private BiFunction<OidcUserRequest, OidcUserInfo, OidcUser> oidcUserMapper = OidcUserRequestUtils::getUser;

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
		if (this.retrieveUserInfo.test(userRequest)) {
			OAuth2User oauth2User = this.oauth2UserService.loadUser(userRequest);
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
		return this.oidcUserMapper.apply(userRequest, userInfo);
	}

	private Map<String, Object> getClaims(OidcUserRequest userRequest, OAuth2User oauth2User) {
		Converter<Map<String, Object>, Map<String, Object>> converter = this.claimTypeConverterFactory
			.apply(userRequest.getClientRegistration());
		if (converter != null) {
			return converter.convert(oauth2User.getAttributes());
		}
		return DEFAULT_CLAIM_TYPE_CONVERTER.convert(oauth2User.getAttributes());
	}

	private boolean shouldRetrieveUserInfo(OidcUserRequest userRequest) {
		// Auto-disabled if UserInfo Endpoint URI is not provided
		ProviderDetails providerDetails = userRequest.getClientRegistration().getProviderDetails();
		if (!StringUtils.hasLength(providerDetails.getUserInfoEndpoint().getUri())) {
			return false;
		}
		// The Claims requested by the profile, email, address, and phone scope values
		// are returned from the UserInfo Endpoint (as described in Section 5.3.2),
		// when a response_type value is used that results in an Access Token being
		// issued.
		// However, when no Access Token is issued, which is the case for the
		// response_type=id_token,
		// the resulting Claims are returned in the ID Token.
		// The Authorization Code Grant Flow, which is response_type=code, results in an
		// Access Token being issued.
		if (AuthorizationGrantType.AUTHORIZATION_CODE
			.equals(userRequest.getClientRegistration().getAuthorizationGrantType())) {
			// Return true if there is at least one match between the authorized scope(s)
			// and accessible scope(s)
			//
			// Also return true if authorized scope(s) is empty, because the provider has
			// not indicated which scopes are accessible via the access token
			// @formatter:off
			return this.accessibleScopes.isEmpty()
					|| CollectionUtils.isEmpty(userRequest.getAccessToken().getScopes())
					|| CollectionUtils.containsAny(userRequest.getAccessToken().getScopes(), this.accessibleScopes);
			// @formatter:on
		}
		return false;
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
	 * Sets the scope(s) that allow access to the user info resource. The default is
	 * {@link OidcScopes#PROFILE profile}, {@link OidcScopes#EMAIL email},
	 * {@link OidcScopes#ADDRESS address} and {@link OidcScopes#PHONE phone}. The scope(s)
	 * are checked against the "granted" scope(s) associated to the
	 * {@link OidcUserRequest#getAccessToken() access token} to determine if the user info
	 * resource is accessible or not. If there is at least one match, the user info
	 * resource will be requested, otherwise it will not.
	 * @param accessibleScopes the scope(s) that allow access to the user info resource
	 * @since 5.2
	 * @deprecated Use {@link #setRetrieveUserInfo(Predicate)} instead
	 */
	@Deprecated(since = "6.3", forRemoval = true)
	public final void setAccessibleScopes(Set<String> accessibleScopes) {
		Assert.notNull(accessibleScopes, "accessibleScopes cannot be null");
		this.accessibleScopes = accessibleScopes;
	}

	/**
	 * Sets the {@code Predicate} used to determine if the UserInfo Endpoint should be
	 * called to retrieve information about the End-User (Resource Owner).
	 * <p>
	 * By default, the UserInfo Endpoint is called if all of the following are true:
	 * <ul>
	 * <li>The user info endpoint is defined on the ClientRegistration</li>
	 * <li>The Client Registration uses the
	 * {@link AuthorizationGrantType#AUTHORIZATION_CODE}</li>
	 * <li>The access token contains one or more scopes allowed to access the UserInfo
	 * Endpoint ({@link OidcScopes#PROFILE profile}, {@link OidcScopes#EMAIL email},
	 * {@link OidcScopes#ADDRESS address} or {@link OidcScopes#PHONE phone}) or the access
	 * token scopes are empty</li>
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
	 * 	public OidcUserService oidcUserService() {
	 * 		var userService = new OidcUserService();
	 * 		userService.setOidcUserMapper(oidcUserMapper());
	 * 		return userService;
	 * 	}
	 *
	 * 	private static BiFunction&lt;OidcUserRequest, OidcUserInfo, OidcUser&gt; oidcUserMapper() {
	 * 		return (userRequest, userInfo) -> {
	 * 			var accessToken = userRequest.getAccessToken();
	 * 			var grantedAuthorities = new HashSet&lt;GrantedAuthority&gt;();
	 * 			// TODO: Map authorities from the access token
	 * 			var userNameAttributeName = "preferred_username";
	 * 			return new DefaultOidcUser(
	 * 				grantedAuthorities,
	 * 				userRequest.getIdToken(),
	 * 				userInfo,
	 * 				userNameAttributeName
	 * 			);
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
	public final void setOidcUserMapper(BiFunction<OidcUserRequest, OidcUserInfo, OidcUser> oidcUserMapper) {
		Assert.notNull(oidcUserMapper, "oidcUserMapper cannot be null");
		this.oidcUserMapper = oidcUserMapper;
	}

}
