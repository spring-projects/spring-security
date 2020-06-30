/*
 * Copyright 2002-2020 the original author or authors.
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

/**
 * Used by {@link EnableWebSecurity} to conditionally import:
 *
 * <ul>
 * 	<li>{@link Saml2ServiceProviderConfiguration} when the {@code spring-security-oauth2-client} module is present on the classpath</li>
 * </ul>
 *
 * @author Josh Cummings
 * @since 5.4
 * @see Saml2ServiceProviderConfiguration
 */
final class Saml2ImportSelector implements ImportSelector {
	@Override
	public String[] selectImports(AnnotationMetadata importingClassMetadata) {
		boolean saml2ServiceProviderPresent = ClassUtils.isPresent(
				"org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration",
				getClass().getClassLoader());

		if (saml2ServiceProviderPresent) {
			return new String[] { "org.springframework.security.config.annotation.web.configuration.Saml2ServiceProviderConfiguration" };
		}

		return new String[0];
	}
}
