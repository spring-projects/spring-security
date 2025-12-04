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

package org.springframework.security.oauth2.server.authorization.aot.hint;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;

/**
 * {@link RuntimeHintsRegistrar} that contributes the required {@link RuntimeHints} for
 * OAuth 2.1 Authorization Server. Statically registered via
 * META-INF/spring/aot.factories.
 *
 * @author Joe Grandja
 * @since 7.0
 */
class OAuth2AuthorizationServerRuntimeHints implements RuntimeHintsRegistrar {

	@Override
	public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
		hints.reflection()
			.registerType(OAuth2AuthorizationCodeRequestAuthenticationProvider.class,
					MemberCategory.INVOKE_DECLARED_METHODS);
		hints.reflection()
			.registerType(OAuth2AuthorizationEndpointFilter.class, MemberCategory.INVOKE_DECLARED_METHODS);
		hints.reflection()
			.registerType(TypeReference
				.of("org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter$OAuth2AuthorizationCodeRequestValidatingFilter"),
					MemberCategory.INVOKE_DECLARED_CONSTRUCTORS);
		hints.reflection()
			.registerType(OAuth2AuthorizationCodeRequestAuthenticationToken.class, MemberCategory.DECLARED_FIELDS);

	}

}
