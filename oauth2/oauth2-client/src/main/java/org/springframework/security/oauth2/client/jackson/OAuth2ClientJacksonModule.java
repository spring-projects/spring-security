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

package org.springframework.security.oauth2.client.jackson;

import tools.jackson.core.Version;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

import org.springframework.security.jackson.SecurityJacksonModule;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

/**
 * Jackson {@code Module} for {@code spring-security-oauth2-client}, that registers the
 * following mix-in annotations:
 *
 * <ul>
 * <li>{@link OAuth2AuthorizationRequestMixin}</li>
 * <li>{@link ClientRegistrationMixin}</li>
 * <li>{@link OAuth2AccessTokenMixin}</li>
 * <li>{@link OAuth2RefreshTokenMixin}</li>
 * <li>{@link OAuth2AuthorizedClientMixin}</li>
 * <li>{@link OAuth2UserAuthorityMixin}</li>
 * <li>{@link DefaultOAuth2UserMixin}</li>
 * <li>{@link OidcIdTokenMixin}</li>
 * <li>{@link OidcUserInfoMixin}</li>
 * <li>{@link OidcUserAuthorityMixin}</li>
 * <li>{@link DefaultOidcUserMixin}</li>
 * <li>{@link OAuth2AuthenticationTokenMixin}</li>
 * <li>{@link OAuth2AuthenticationExceptionMixin}</li>
 * <li>{@link OAuth2ErrorMixin}</li>
 * </ul>
 *
 * <p>
 * The recommended way to configure it is to use {@link SecurityJacksonModules} in order
 * to enable properly automatic inclusion of type information with related validation.
 *
 * <pre>
 *     ClassLoader loader = getClass().getClassLoader();
 *     JsonMapper mapper = JsonMapper.builder()
 * 				.addModules(SecurityJacksonModules.getModules(loader))
 * 				.build();
 * </pre>
 *
 * @author Sebastien Deleuze
 * @author Joe Grandja
 * @since 7.0
 */
@SuppressWarnings("serial")
public class OAuth2ClientJacksonModule extends SecurityJacksonModule {

	public OAuth2ClientJacksonModule() {
		super(OAuth2ClientJacksonModule.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void configurePolymorphicTypeValidator(BasicPolymorphicTypeValidator.Builder builder) {
		builder.allowIfSubType(OAuth2AuthenticationException.class)
			.allowIfSubType(DefaultOidcUser.class)
			.allowIfSubType(OAuth2AuthorizationRequest.class)
			.allowIfSubType(OAuth2Error.class)
			.allowIfSubType(OAuth2AuthorizedClient.class)
			.allowIfSubType(OidcIdToken.class)
			.allowIfSubType(OidcUserInfo.class)
			.allowIfSubType(DefaultOAuth2User.class)
			.allowIfSubType(ClientRegistration.class)
			.allowIfSubType(OAuth2AccessToken.class)
			.allowIfSubType(OAuth2RefreshToken.class)
			.allowIfSubType(OAuth2AuthenticationToken.class)
			.allowIfSubType(OidcUserAuthority.class)
			.allowIfSubType(OAuth2UserAuthority.class);
	}

	@Override
	public void setupModule(SetupContext context) {
		context.setMixIn(OAuth2AuthorizationRequest.class, OAuth2AuthorizationRequestMixin.class);
		context.setMixIn(ClientRegistration.class, ClientRegistrationMixin.class);
		context.setMixIn(OAuth2AccessToken.class, OAuth2AccessTokenMixin.class);
		context.setMixIn(OAuth2RefreshToken.class, OAuth2RefreshTokenMixin.class);
		context.setMixIn(OAuth2AuthorizedClient.class, OAuth2AuthorizedClientMixin.class);
		context.setMixIn(OAuth2UserAuthority.class, OAuth2UserAuthorityMixin.class);
		context.setMixIn(DefaultOAuth2User.class, DefaultOAuth2UserMixin.class);
		context.setMixIn(OidcIdToken.class, OidcIdTokenMixin.class);
		context.setMixIn(OidcUserInfo.class, OidcUserInfoMixin.class);
		context.setMixIn(OidcUserAuthority.class, OidcUserAuthorityMixin.class);
		context.setMixIn(DefaultOidcUser.class, DefaultOidcUserMixin.class);
		context.setMixIn(OAuth2AuthenticationToken.class, OAuth2AuthenticationTokenMixin.class);
		context.setMixIn(OAuth2AuthenticationException.class, OAuth2AuthenticationExceptionMixin.class);
		context.setMixIn(OAuth2Error.class, OAuth2ErrorMixin.class);
	}

}
