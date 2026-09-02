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

package org.springframework.security.oauth2.client.aot.hint;

import java.util.List;

import org.jspecify.annotations.Nullable;

import org.springframework.aot.hint.BindingReflectionHintsRegistrar;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import org.springframework.util.ClassUtils;

/**
 * {@link RuntimeHintsRegistrar} for OAuth2 Client
 *
 * @author Marcus Da Coregio
 * @since 6.0
 */
class OAuth2ClientRuntimeHints implements RuntimeHintsRegistrar {

	private static final boolean r2dbcPresent;

	static {
		ClassLoader classLoader = ClassUtils.getDefaultClassLoader();
		r2dbcPresent = ClassUtils.isPresent("io.r2dbc.spi.Row", classLoader)
				&& ClassUtils.isPresent("org.springframework.r2dbc.core.DatabaseClient", classLoader);
	}

	private final BindingReflectionHintsRegistrar bindingReflectionHintsRegistrar = new BindingReflectionHintsRegistrar();

	@Override
	public void registerHints(RuntimeHints hints, @Nullable ClassLoader classLoader) {
		registerOAuth2ClientSchemaFilesHints(hints);
		registerJacksonHints(hints, classLoader);
		if (r2dbcPresent) {
			registerR2dbcHints(hints);
		}
	}

	private void registerJacksonHints(RuntimeHints hints, @Nullable ClassLoader classLoader) {
		ClassLoader loader = (classLoader != null) ? classLoader : ClassUtils.getDefaultClassLoader();
		boolean jackson2Present = ClassUtils.isPresent("com.fasterxml.jackson.databind.ObjectMapper", loader)
				&& ClassUtils.isPresent("com.fasterxml.jackson.core.JsonGenerator", loader);
		boolean jackson3Present = ClassUtils.isPresent("tools.jackson.databind.json.JsonMapper", loader);
		if (!jackson2Present && !jackson3Present) {
			return;
		}
		hints.reflection()
			.registerTypes(getOAuth2ClientTypes(),
					(builder) -> builder.withMembers(MemberCategory.ACCESS_DECLARED_FIELDS,
							MemberCategory.INVOKE_DECLARED_CONSTRUCTORS, MemberCategory.INVOKE_DECLARED_METHODS));
		if (jackson2Present) {
			registerJacksonModule(hints,
					"org.springframework.security.oauth2.client.jackson2.OAuth2ClientJackson2Module");
			registerJacksonMixins(hints, loader, "org.springframework.security.oauth2.client.jackson2");
		}
		if (jackson3Present) {
			registerJacksonModule(hints,
					"org.springframework.security.oauth2.client.jackson.OAuth2ClientJacksonModule");
			registerJacksonMixins(hints, loader, "org.springframework.security.oauth2.client.jackson");
		}
	}

	private List<TypeReference> getOAuth2ClientTypes() {
		return List.of(TypeReference.of("org.springframework.security.oauth2.client.OAuth2AuthorizedClient"),
				TypeReference.of("org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken"),
				TypeReference.of("org.springframework.security.oauth2.client.registration.ClientRegistration"),
				TypeReference.of("org.springframework.security.oauth2.core.OAuth2AccessToken"),
				TypeReference.of("org.springframework.security.oauth2.core.OAuth2AuthenticationException"),
				TypeReference.of("org.springframework.security.oauth2.core.OAuth2Error"),
				TypeReference.of("org.springframework.security.oauth2.core.OAuth2RefreshToken"),
				TypeReference.of("org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest"),
				TypeReference.of("org.springframework.security.oauth2.core.oidc.OidcIdToken"),
				TypeReference.of("org.springframework.security.oauth2.core.oidc.OidcUserInfo"),
				TypeReference.of("org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser"),
				TypeReference.of("org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority"),
				TypeReference.of("org.springframework.security.oauth2.core.user.DefaultOAuth2User"),
				TypeReference.of("org.springframework.security.oauth2.core.user.OAuth2UserAuthority"));
	}

	private void registerJacksonModule(RuntimeHints hints, String moduleClassName) {
		hints.reflection().registerType(TypeReference.of(moduleClassName), MemberCategory.INVOKE_DECLARED_CONSTRUCTORS);
	}

	private void registerJacksonMixins(RuntimeHints hints, @Nullable ClassLoader classLoader, String packageName) {
		String[] mixinClassNames = { "ClientRegistrationMixin", "DefaultOAuth2UserMixin", "DefaultOidcUserMixin",
				"OAuth2AccessTokenMixin", "OAuth2AuthenticationExceptionMixin", "OAuth2AuthenticationTokenMixin",
				"OAuth2AuthorizationRequestMixin", "OAuth2AuthorizedClientMixin", "OAuth2ErrorMixin",
				"OAuth2RefreshTokenMixin", "OAuth2UserAuthorityMixin", "OidcIdTokenMixin", "OidcUserAuthorityMixin",
				"OidcUserInfoMixin" };
		for (String mixinClassName : mixinClassNames) {
			Class<?> mixinClass = ClassUtils.resolveClassName(packageName + "." + mixinClassName, classLoader);
			this.bindingReflectionHintsRegistrar.registerReflectionHints(hints.reflection(), mixinClass);
		}
	}

	private void registerOAuth2ClientSchemaFilesHints(RuntimeHints hints) {
		hints.resources()
			.registerPattern("org/springframework/security/oauth2/client/oauth2-client-schema.sql")
			.registerPattern("org/springframework/security/oauth2/client/oauth2-client-schema-postgres.sql");
	}

	private void registerR2dbcHints(RuntimeHints hints) {
		// Register R2DBC OAuth2 client service types
		hints.reflection()
			.registerType(
					TypeReference
						.of("org.springframework.security.oauth2.client.R2dbcReactiveOAuth2AuthorizedClientService"),
					(builder) -> builder.withMembers(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
							MemberCategory.INVOKE_DECLARED_METHODS, MemberCategory.ACCESS_DECLARED_FIELDS));

		// Register OAuth2 client types that may be serialized in R2DBC scenarios
		hints.reflection()
			.registerTypes(java.util.List.of(
					TypeReference.of("org.springframework.security.oauth2.client.OAuth2AuthorizedClient"),
					TypeReference
						.of("org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken")),
					(builder) -> builder.withMembers(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
							MemberCategory.INVOKE_DECLARED_METHODS, MemberCategory.ACCESS_DECLARED_FIELDS));
	}

}
