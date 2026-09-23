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

import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import org.springframework.aot.hint.predicate.RuntimeHintsPredicates;
import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.util.ClassUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2ClientRuntimeHints}
 */
class OAuth2ClientRuntimeHintsTests {

	private final RuntimeHints hints = new RuntimeHints();

	@BeforeEach
	void setup() {
		SpringFactoriesLoader.forResourceLocation("META-INF/spring/aot.factories")
			.load(RuntimeHintsRegistrar.class)
			.forEach((registrar) -> registrar.registerHints(this.hints, ClassUtils.getDefaultClassLoader()));
	}

	@ParameterizedTest
	@MethodSource("getOAuth2ClientSchemaFiles")
	void oauth2ClientSchemaFilesHasHints(String schemaFile) {
		assertThat(RuntimeHintsPredicates.resource().forResource(schemaFile)).accepts(this.hints);
	}

	private static Stream<String> getOAuth2ClientSchemaFiles() {
		return Stream.of("org/springframework/security/oauth2/client/oauth2-client-schema.sql",
				"org/springframework/security/oauth2/client/oauth2-client-schema-postgres.sql");
	}

	@ParameterizedTest
	@MethodSource("getJacksonModuleTypes")
	void jacksonModulesHaveHints(TypeReference moduleType) {
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(moduleType)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS)).accepts(this.hints);
	}

	private static Stream<TypeReference> getJacksonModuleTypes() {
		return Stream.of(
				TypeReference.of("org.springframework.security.oauth2.client.jackson2.OAuth2ClientJackson2Module"),
				TypeReference.of("org.springframework.security.oauth2.client.jackson.OAuth2ClientJacksonModule"));
	}

	@Test
	void jacksonHintsUseProvidedClassLoader() {
		assertJacksonModuleVisibility(hideClasses("tools.jackson.databind.json.JsonMapper"), true, false);
		assertJacksonModuleVisibility(
				hideClasses("com.fasterxml.jackson.databind.ObjectMapper", "com.fasterxml.jackson.core.JsonGenerator"),
				false, true);
		assertJacksonModuleVisibility(hideClasses("com.fasterxml.jackson.databind.ObjectMapper",
				"com.fasterxml.jackson.core.JsonGenerator", "tools.jackson.databind.json.JsonMapper"), false, false);
	}

	private void assertJacksonModuleVisibility(ClassLoader classLoader, boolean jackson2, boolean jackson3) {
		RuntimeHints hints = new RuntimeHints();
		new OAuth2ClientRuntimeHints().registerHints(hints, classLoader);
		assertThat(hints.reflection()
			.getTypeHint(TypeReference
				.of("org.springframework.security.oauth2.client.jackson2.OAuth2ClientJackson2Module")) != null)
			.isEqualTo(jackson2);
		assertThat(hints.reflection()
			.getTypeHint(TypeReference
				.of("org.springframework.security.oauth2.client.jackson.OAuth2ClientJacksonModule")) != null)
			.isEqualTo(jackson3);
	}

	private static ClassLoader hideClasses(String... classNames) {
		Set<String> hiddenClasses = Set.of(classNames);
		return new ClassLoader(ClassUtils.getDefaultClassLoader()) {
			@Override
			protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
				if (hiddenClasses.contains(name)) {
					throw new ClassNotFoundException(name);
				}
				return super.loadClass(name, resolve);
			}
		};
	}

	@Test
	void authorizationRequestHasBindingHints() {
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(TypeReference.of("org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest"))
			.withMemberCategories(MemberCategory.ACCESS_DECLARED_FIELDS, MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
					MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.hints);
	}

	@ParameterizedTest
	@MethodSource("getJacksonDeserializerTypes")
	void jacksonDeserializersHaveHints(TypeReference deserializerType) {
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(deserializerType)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS)).accepts(this.hints);
	}

	private static Stream<TypeReference> getJacksonDeserializerTypes() {
		return Stream.of(
				TypeReference.of("org.springframework.security.oauth2.client.jackson2.ClientRegistrationDeserializer"),
				TypeReference
					.of("org.springframework.security.oauth2.client.jackson2.OAuth2AuthorizationRequestDeserializer"),
				TypeReference.of("org.springframework.security.oauth2.client.jackson.ClientRegistrationDeserializer"),
				TypeReference
					.of("org.springframework.security.oauth2.client.jackson.OAuth2AuthorizationRequestDeserializer"));
	}

}
