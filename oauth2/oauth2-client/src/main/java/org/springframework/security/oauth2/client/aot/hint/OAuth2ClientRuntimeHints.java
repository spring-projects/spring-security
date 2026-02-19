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

import org.jspecify.annotations.Nullable;

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

	@Override
	public void registerHints(RuntimeHints hints, @Nullable ClassLoader classLoader) {
		registerOAuth2ClientSchemaFilesHints(hints);
		if (r2dbcPresent) {
			registerR2dbcHints(hints);
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
			.registerTypes(
					java.util.List.of(
							TypeReference
								.of("org.springframework.security.oauth2.client.OAuth2AuthorizedClient"),
							TypeReference
								.of("org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken")),
					(builder) -> builder.withMembers(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
							MemberCategory.INVOKE_DECLARED_METHODS, MemberCategory.ACCESS_DECLARED_FIELDS));
	}

}
