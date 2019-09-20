/*
 * Copyright 2002-2018 the original author or authors.
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

import java.util.ArrayList;
import java.util.List;

import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.util.ClassUtils;

/**
 * Used by {@link EnableWebSecurity} to conditionally import {@link OAuth2ClientConfiguration}
 * when the {@code spring-security-oauth2-client} module is present on the classpath and
 * {@link OAuth2ResourceServerConfiguration} when the {@code spring-security-oauth2-resource-server}
 * module is on the classpath.
 *
 * @author Joe Grandja
 * @author Josh Cummings
 * @since 5.1
 * @see OAuth2ClientConfiguration
 */
final class OAuth2ImportSelector implements ImportSelector {

	@Override
	public String[] selectImports(AnnotationMetadata importingClassMetadata) {
		List<String> imports = new ArrayList<>();

		if (ClassUtils.isPresent(
			"org.springframework.security.oauth2.client.registration.ClientRegistration", getClass().getClassLoader())) {
			imports.add("org.springframework.security.config.annotation.web.configuration.OAuth2ClientConfiguration");
		}

		if (ClassUtils.isPresent(
			"org.springframework.security.oauth2.server.resource.BearerTokenError", getClass().getClassLoader())) {
			imports.add("org.springframework.security.config.annotation.web.configuration.OAuth2ResourceServerConfiguration");
		}

		return imports.toArray(new String[0]);
	}
}
