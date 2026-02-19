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

package org.springframework.security.saml2.aot.hint;

import org.jspecify.annotations.Nullable;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AssertionAuthentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2ResponseAssertion;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.util.ClassUtils;

/**
 * {@link RuntimeHintsRegistrar} for SAML2 Service Provider classes.
 *
 * @author Josh Long
 */
class Saml2RuntimeHints implements RuntimeHintsRegistrar {

	private static final boolean jackson2Present;

	private static final boolean jackson3Present;

	static {
		ClassLoader classLoader = ClassUtils.getDefaultClassLoader();
		jackson2Present = ClassUtils.isPresent("com.fasterxml.jackson.databind.ObjectMapper", classLoader)
				&& ClassUtils.isPresent("com.fasterxml.jackson.core.JsonGenerator", classLoader);
		jackson3Present = ClassUtils.isPresent("tools.jackson.databind.json.JsonMapper", classLoader);
	}

	@Override
	public void registerHints(RuntimeHints hints, @Nullable ClassLoader classLoader) {
		registerAuthenticationHints(hints);
		registerJacksonHints(hints);
		registerJdbcSchemaHints(hints);
	}

	private void registerAuthenticationHints(RuntimeHints hints) {
		hints.reflection()
			.registerTypes(
					java.util.List.of(TypeReference.of(Saml2Authentication.class),
							TypeReference.of(Saml2AssertionAuthentication.class),
							TypeReference.of(DefaultSaml2AuthenticatedPrincipal.class),
							TypeReference.of(Saml2PostAuthenticationRequest.class),
							TypeReference.of(Saml2RedirectAuthenticationRequest.class),
							TypeReference.of(Saml2ResponseAssertion.class), TypeReference.of(Saml2LogoutRequest.class),
							TypeReference.of(Saml2Error.class), TypeReference.of(Saml2AuthenticationException.class)),
					(builder) -> builder.withMembers(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
							MemberCategory.INVOKE_DECLARED_METHODS, MemberCategory.ACCESS_DECLARED_FIELDS));
	}

	private void registerJacksonHints(RuntimeHints hints) {
		// Jackson 2 Module
		if (jackson2Present) {
			// Register mixins for Jackson 2
			registerJackson2Mixins(hints);
		}

		// Jackson 3 Module
		if (jackson3Present) {
			// Register mixins for Jackson 3
			registerJackson3Mixins(hints);
		}
	}

	private void registerJackson2Mixins(RuntimeHints hints) {
		String[] mixinClasses = { "org.springframework.security.saml2.jackson2.Saml2AuthenticationMixin",
				"org.springframework.security.saml2.jackson2.Saml2JacksonModule",
				"org.springframework.security.saml2.jackson2.Saml2AssertionAuthenticationMixin",
				"org.springframework.security.saml2.jackson2.SimpleSaml2ResponseAssertionAccessorMixin",
				"org.springframework.security.saml2.jackson2.DefaultSaml2AuthenticatedPrincipalMixin",
				"org.springframework.security.saml2.jackson2.Saml2LogoutRequestMixin",
				"org.springframework.security.saml2.jackson2.Saml2RedirectAuthenticationRequestMixin",
				"org.springframework.security.saml2.jackson2.Saml2PostAuthenticationRequestMixin",
				"org.springframework.security.saml2.jackson2.Saml2ErrorMixin",
				"org.springframework.security.saml2.jackson2.Saml2AuthenticationExceptionMixin" };

		for (String mixinClass : mixinClasses) {
			hints.reflection()
				.registerType(TypeReference.of(mixinClass),
						(builder) -> builder.withMembers(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
								MemberCategory.INVOKE_DECLARED_METHODS, MemberCategory.ACCESS_DECLARED_FIELDS));
		}
	}

	private void registerJackson3Mixins(RuntimeHints hints) {
		String[] mixinClasses = { "org.springframework.security.saml2.jackson.Saml2AuthenticationMixin",
				"org.springframework.security.saml2.jackson.Saml2AssertionAuthenticationMixin",
				"org.springframework.security.saml2.jackson.Saml2JacksonModule",
				"org.springframework.security.saml2.jackson.SimpleSaml2ResponseAssertionAccessorMixin",
				"org.springframework.security.saml2.jackson.DefaultSaml2AuthenticatedPrincipalMixin",
				"org.springframework.security.saml2.jackson.Saml2LogoutRequestMixin",
				"org.springframework.security.saml2.jackson.Saml2RedirectAuthenticationRequestMixin",
				"org.springframework.security.saml2.jackson.Saml2PostAuthenticationRequestMixin",
				"org.springframework.security.saml2.jackson.Saml2ErrorMixin",
				"org.springframework.security.saml2.jackson.Saml2AuthenticationExceptionMixin" };

		for (String mixinClass : mixinClasses) {
			hints.reflection()
				.registerType(TypeReference.of(mixinClass),
						(builder) -> builder.withMembers(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
								MemberCategory.INVOKE_DECLARED_METHODS, MemberCategory.ACCESS_DECLARED_FIELDS));
		}
	}

	private void registerJdbcSchemaHints(RuntimeHints hints) {
		hints.resources()
			.registerPattern("org/springframework/security/saml2/saml2-asserting-party-metadata-schema.sql")
			.registerPattern("org/springframework/security/saml2/saml2-asserting-party-metadata-schema-postgres.sql");
	}

}
