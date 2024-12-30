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

package org.springframework.security.web.aot.hint;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;

/**
 * {@link RuntimeHintsRegistrar} for WebMVC classes
 *
 * @author Marcus Da Coregio
 * @author Daniel Garnier-Moiroux
 * @since 6.0
 */
class WebMvcSecurityRuntimeHints implements RuntimeHintsRegistrar {

	@Override
	public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
		hints.reflection()
			.registerType(WebSecurityExpressionRoot.class, (builder) -> builder
				.withMembers(MemberCategory.INVOKE_DECLARED_METHODS, MemberCategory.DECLARED_FIELDS));
		hints.reflection()
			.registerType(
					TypeReference
						.of("org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler$SupplierCsrfToken"),
					MemberCategory.INVOKE_DECLARED_METHODS);

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

}
