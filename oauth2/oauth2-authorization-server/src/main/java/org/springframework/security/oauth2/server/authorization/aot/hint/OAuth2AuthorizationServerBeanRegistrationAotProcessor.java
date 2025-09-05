/*
 * Copyright 2020-2024 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.aot.hint;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import org.springframework.aot.generate.GenerationContext;
import org.springframework.aot.hint.BindingReflectionHintsRegistrar;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.TypeReference;
import org.springframework.beans.factory.aot.BeanRegistrationAotContribution;
import org.springframework.beans.factory.aot.BeanRegistrationAotProcessor;
import org.springframework.beans.factory.aot.BeanRegistrationCode;
import org.springframework.beans.factory.support.RegisteredBean;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.jackson2.CoreJackson2Module;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeActor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.jackson2.WebServletJackson2Module;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.util.ClassUtils;

/**
 * {@link BeanRegistrationAotProcessor} that detects specific registered beans and
 * contributes the required {@link RuntimeHints}. Statically registered via
 * META-INF/spring/aot.factories.
 *
 * @author Joe Grandja
 * @author Josh Long
 * @author William Koch
 * @since 1.2
 */
class OAuth2AuthorizationServerBeanRegistrationAotProcessor implements BeanRegistrationAotProcessor {

	private boolean jackson2Contributed;

	@Override
	public BeanRegistrationAotContribution processAheadOfTime(RegisteredBean registeredBean) {
		boolean isJdbcBasedOAuth2AuthorizationService = JdbcOAuth2AuthorizationService.class
			.isAssignableFrom(registeredBean.getBeanClass());

		boolean isJdbcBasedRegisteredClientRepository = JdbcRegisteredClientRepository.class
			.isAssignableFrom(registeredBean.getBeanClass());

		// @formatter:off
		if ((isJdbcBasedOAuth2AuthorizationService || isJdbcBasedRegisteredClientRepository)
				&& !this.jackson2Contributed) {
			Jackson2ConfigurationBeanRegistrationAotContribution jackson2Contribution =
					new Jackson2ConfigurationBeanRegistrationAotContribution();
			this.jackson2Contributed = true;
			return jackson2Contribution;
		}
		// @formatter:on
		return null;
	}

	private static class Jackson2ConfigurationBeanRegistrationAotContribution
			implements BeanRegistrationAotContribution {

		private final BindingReflectionHintsRegistrar reflectionHintsRegistrar = new BindingReflectionHintsRegistrar();

		@Override
		public void applyTo(GenerationContext generationContext, BeanRegistrationCode beanRegistrationCode) {
			registerHints(generationContext.getRuntimeHints());
		}

		private void registerHints(RuntimeHints hints) {
			// Collections -> UnmodifiableSet, UnmodifiableList, UnmodifiableMap,
			// UnmodifiableRandomAccessList, etc.
			hints.reflection().registerType(Collections.class, MemberCategory.DECLARED_CLASSES);

			// HashSet
			hints.reflection()
				.registerType(HashSet.class, MemberCategory.DECLARED_FIELDS,
						MemberCategory.INVOKE_DECLARED_CONSTRUCTORS, MemberCategory.INVOKE_DECLARED_METHODS);

			// Spring Security and Spring Authorization Server
			hints.reflection()
				.registerTypes(Arrays.asList(TypeReference.of(AbstractAuthenticationToken.class),
						TypeReference.of(DefaultSavedRequest.Builder.class),
						TypeReference.of(WebAuthenticationDetails.class),
						TypeReference.of(UsernamePasswordAuthenticationToken.class), TypeReference.of(User.class),
						TypeReference.of(DefaultOidcUser.class), TypeReference.of(DefaultOAuth2User.class),
						TypeReference.of(OidcUserAuthority.class), TypeReference.of(OAuth2UserAuthority.class),
						TypeReference.of(SimpleGrantedAuthority.class), TypeReference.of(OidcIdToken.class),
						TypeReference.of(AbstractOAuth2Token.class), TypeReference.of(OidcUserInfo.class),
						TypeReference.of(OAuth2TokenExchangeActor.class),
						TypeReference.of(OAuth2AuthorizationRequest.class),
						TypeReference.of(OAuth2TokenExchangeCompositeAuthenticationToken.class),
						TypeReference.of(AuthorizationGrantType.class),
						TypeReference.of(OAuth2AuthorizationResponseType.class),
						TypeReference.of(OAuth2TokenFormat.class)),
						(builder) -> builder.withMembers(MemberCategory.DECLARED_FIELDS,
								MemberCategory.INVOKE_DECLARED_CONSTRUCTORS, MemberCategory.INVOKE_DECLARED_METHODS));

			// Jackson Modules - Spring Security and Spring Authorization Server
			hints.reflection()
				.registerTypes(
						Arrays.asList(TypeReference.of(CoreJackson2Module.class),
								TypeReference.of(WebServletJackson2Module.class),
								TypeReference.of(OAuth2AuthorizationServerJackson2Module.class)),
						(builder) -> builder.withMembers(MemberCategory.DECLARED_FIELDS,
								MemberCategory.INVOKE_DECLARED_CONSTRUCTORS, MemberCategory.INVOKE_DECLARED_METHODS));

			// Jackson Mixins - Spring Security and Spring Authorization Server
			this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(),
					loadClass("org.springframework.security.jackson2.UnmodifiableSetMixin"));
			this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(),
					loadClass("org.springframework.security.jackson2.UnmodifiableListMixin"));
			this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(),
					loadClass("org.springframework.security.jackson2.UnmodifiableMapMixin"));
			this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(), loadClass(
					"org.springframework.security.oauth2.server.authorization.jackson2.UnmodifiableMapMixin"));
			this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(),
					loadClass("org.springframework.security.oauth2.server.authorization.jackson2.HashSetMixin"));
			this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(),
					loadClass("org.springframework.security.web.jackson2.DefaultSavedRequestMixin"));
			this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(),
					loadClass("org.springframework.security.web.jackson2.WebAuthenticationDetailsMixin"));
			this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(),
					loadClass("org.springframework.security.jackson2.UsernamePasswordAuthenticationTokenMixin"));
			this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(),
					loadClass("org.springframework.security.jackson2.UserMixin"));
			this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(),
					loadClass("org.springframework.security.jackson2.SimpleGrantedAuthorityMixin"));
			this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(), loadClass(
					"org.springframework.security.oauth2.server.authorization.jackson2.OAuth2TokenExchangeActorMixin"));
			this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(), loadClass(
					"org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationRequestMixin"));
			this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(), loadClass(
					"org.springframework.security.oauth2.server.authorization.jackson2.OAuth2TokenExchangeCompositeAuthenticationTokenMixin"));
			this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(), loadClass(
					"org.springframework.security.oauth2.server.authorization.jackson2.OAuth2TokenFormatMixin"));

			// Check if Spring Security OAuth2 Client is on classpath
			if (ClassUtils.isPresent("org.springframework.security.oauth2.client.registration.ClientRegistration",
					ClassUtils.getDefaultClassLoader())) {

				// Jackson Module (and required types) - Spring Security OAuth2 Client
				hints.reflection()
					.registerTypes(Arrays.asList(
							TypeReference
								.of("org.springframework.security.oauth2.client.jackson2.OAuth2ClientJackson2Module"),
							TypeReference
								.of("org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken")),
							(builder) -> builder.withMembers(MemberCategory.DECLARED_FIELDS,
									MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
									MemberCategory.INVOKE_DECLARED_METHODS));

				// Jackson Mixins - Spring Security OAuth2 Client
				this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(), loadClass(
						"org.springframework.security.oauth2.client.jackson2.OAuth2AuthenticationTokenMixin"));
				this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(),
						loadClass("org.springframework.security.oauth2.client.jackson2.DefaultOidcUserMixin"));
				this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(),
						loadClass("org.springframework.security.oauth2.client.jackson2.DefaultOAuth2UserMixin"));
				this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(),
						loadClass("org.springframework.security.oauth2.client.jackson2.OidcUserAuthorityMixin"));
				this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(),
						loadClass("org.springframework.security.oauth2.client.jackson2.OAuth2UserAuthorityMixin"));
				this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(),
						loadClass("org.springframework.security.oauth2.client.jackson2.OidcIdTokenMixin"));
				this.reflectionHintsRegistrar.registerReflectionHints(hints.reflection(),
						loadClass("org.springframework.security.oauth2.client.jackson2.OidcUserInfoMixin"));
			}
		}

		private static Class<?> loadClass(String className) {
			try {
				return Class.forName(className);
			}
			catch (ClassNotFoundException ex) {
				throw new RuntimeException(ex);
			}
		}

	}

}
