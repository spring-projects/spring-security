/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.config.annotation.web.configuration;

import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.util.ClassUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Used by {@link EnableWebSecurity} to conditionally import:
 *
 * <ul>
 * 	<li>{@link OAuth2ClientConfiguration} when the {@code spring-security-oauth2-client} module is present on the classpath</li>
 * 	<li>{@link SecurityReactorContextConfiguration} when the {@code spring-webflux} and {@code spring-security-oauth2-client} module is present on the classpath</li>
 * 	<li>{@link OAuth2ResourceServerConfiguration} when the {@code spring-security-oauth2-resource-server} module is present on the classpath</li>
 * </ul>
 *
 * @author Joe Grandja
 * @author Josh Cummings
 * @since 5.1
 * @see OAuth2ClientConfiguration
 * @see SecurityReactorContextConfiguration
 * @see OAuth2ResourceServerConfiguration
 */
final class OAuth2ImportSelector implements ImportSelector {

	@Override
	public String[] selectImports(AnnotationMetadata importingClassMetadata) {
		List<String> imports = new ArrayList<>();

		boolean oauth2ClientPresent = ClassUtils.isPresent(
				"org.springframework.security.oauth2.client.registration.ClientRegistration", getClass().getClassLoader());
		if (oauth2ClientPresent) {
			imports.add("org.springframework.security.config.annotation.web.configuration.OAuth2ClientConfiguration");
		}

		boolean webfluxPresent = ClassUtils.isPresent(
				"org.springframework.web.reactive.function.client.ExchangeFilterFunction", getClass().getClassLoader());
		if (webfluxPresent && oauth2ClientPresent) {
			imports.add("org.springframework.security.config.annotation.web.configuration.SecurityReactorContextConfiguration");
		}

		if (ClassUtils.isPresent(
				"org.springframework.security.oauth2.server.resource.BearerTokenError", getClass().getClassLoader())) {
			imports.add("org.springframework.security.config.annotation.web.configuration.OAuth2ResourceServerConfiguration");
		}

		return imports.toArray(new String[0]);
	}
}
