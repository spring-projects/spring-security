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

package org.springframework.security.web.aot.hint;

import java.util.ArrayList;
import java.util.List;

import org.jspecify.annotations.Nullable;

import org.springframework.aot.hint.BindingReflectionHintsRegistrar;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.ClassUtils;

/**
 * {@link RuntimeHintsRegistrar} for web classes
 *
 * @author Marcus Da Coregio
 * @author Daniel Garnier-Moiroux
 * @since 6.0
 */
class WebMvcSecurityRuntimeHints implements RuntimeHintsRegistrar {

	private final BindingReflectionHintsRegistrar bindingReflectionHintsRegistrar = new BindingReflectionHintsRegistrar();

	@Override
	public void registerHints(RuntimeHints hints, @Nullable ClassLoader classLoader) {
		hints.reflection()
			.registerType(WebSecurityExpressionRoot.class, (builder) -> builder
				.withMembers(MemberCategory.INVOKE_DECLARED_METHODS, MemberCategory.ACCESS_DECLARED_FIELDS));
		hints.reflection()
			.registerType(
					TypeReference
						.of("org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler$SupplierCsrfToken"),
					MemberCategory.INVOKE_DECLARED_METHODS);
		hints.reflection()
			.registerType(PreAuthenticatedAuthenticationToken.class,
					(builder) -> builder.withMembers(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
							MemberCategory.INVOKE_DECLARED_METHODS, MemberCategory.ACCESS_DECLARED_FIELDS));
		registerJacksonHints(hints, classLoader);

		ClassPathResource css = new ClassPathResource("org/springframework/security/default-ui.css");
		if (css.exists()) {
			hints.resources().registerResource(css);
		}

		ClassPathResource webauthnJavascript = new ClassPathResource(
				"org/springframework/security/spring-security-webauthn.js");
		if (webauthnJavascript.exists()) {
			hints.resources().registerResource(webauthnJavascript);
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
		boolean servletPresent = ClassUtils.isPresent("jakarta.servlet.http.Cookie", loader);
		hints.reflection()
			.registerTypes(getWebTypes(servletPresent),
					(builder) -> builder.withMembers(MemberCategory.ACCESS_DECLARED_FIELDS,
							MemberCategory.INVOKE_DECLARED_CONSTRUCTORS, MemberCategory.INVOKE_DECLARED_METHODS));
		if (jackson2Present) {
			registerJacksonModule(hints, "org.springframework.security.web.jackson2.WebJackson2Module");
			registerJacksonModule(hints, "org.springframework.security.web.server.jackson2.WebServerJackson2Module");
			registerJacksonMixins(hints, loader, "org.springframework.security.web.jackson2", "DefaultCsrfTokenMixin",
					"PreAuthenticatedAuthenticationTokenMixin", "SwitchUserGrantedAuthorityMixIn");
			registerJacksonMixins(hints, loader, "org.springframework.security.web.server.jackson2",
					"DefaultCsrfServerTokenMixin");
			if (servletPresent) {
				registerJacksonModule(hints, "org.springframework.security.web.jackson2.WebServletJackson2Module");
				registerJacksonMixins(hints, loader, "org.springframework.security.web.jackson2", "CookieMixin",
						"DefaultSavedRequestMixin", "SavedCookieMixin", "WebAuthenticationDetailsMixin");
			}
		}
		if (jackson3Present) {
			registerJacksonModule(hints, "org.springframework.security.web.jackson.WebJacksonModule");
			registerJacksonModule(hints, "org.springframework.security.web.server.jackson.WebServerJacksonModule");
			registerJacksonMixins(hints, loader, "org.springframework.security.web.jackson", "DefaultCsrfTokenMixin",
					"PreAuthenticatedAuthenticationTokenMixin", "SwitchUserGrantedAuthorityMixIn");
			registerJacksonMixins(hints, loader, "org.springframework.security.web.server.jackson",
					"DefaultCsrfServerTokenMixin");
			if (servletPresent) {
				registerJacksonModule(hints, "org.springframework.security.web.jackson.WebServletJacksonModule");
				registerJacksonMixins(hints, loader, "org.springframework.security.web.jackson", "CookieMixin",
						"DefaultSavedRequestMixin", "SavedCookieMixin", "WebAuthenticationDetailsMixin");
			}
		}
	}

	private List<TypeReference> getWebTypes(boolean servletPresent) {
		List<TypeReference> types = new ArrayList<>(List.of(
				TypeReference
					.of("org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken"),
				TypeReference
					.of("org.springframework.security.web.authentication.switchuser.SwitchUserGrantedAuthority"),
				TypeReference.of("org.springframework.security.web.csrf.DefaultCsrfToken"),
				TypeReference.of("org.springframework.security.web.server.csrf.DefaultCsrfToken")));
		if (servletPresent) {
			types.addAll(List.of(TypeReference.of("jakarta.servlet.http.Cookie"),
					TypeReference.of("org.springframework.security.web.authentication.WebAuthenticationDetails"),
					TypeReference.of("org.springframework.security.web.savedrequest.DefaultSavedRequest"),
					TypeReference.of("org.springframework.security.web.savedrequest.DefaultSavedRequest$Builder"),
					TypeReference.of("org.springframework.security.web.savedrequest.SavedCookie")));
		}
		return types;
	}

	private void registerJacksonModule(RuntimeHints hints, String moduleClassName) {
		hints.reflection().registerType(TypeReference.of(moduleClassName), MemberCategory.INVOKE_DECLARED_CONSTRUCTORS);
	}

	private void registerJacksonMixins(RuntimeHints hints, @Nullable ClassLoader classLoader, String packageName,
			String... mixinClassNames) {
		for (String mixinClassName : mixinClassNames) {
			Class<?> mixinClass = ClassUtils.resolveClassName(packageName + "." + mixinClassName, classLoader);
			this.bindingReflectionHintsRegistrar.registerReflectionHints(hints.reflection(), mixinClass);
		}
	}

}
