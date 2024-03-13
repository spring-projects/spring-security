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

package org.springframework.security.config.annotation.web.reactive;

import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.util.ClassUtils;

/**
 * Used by {@link EnableWebFluxSecurity} to conditionally import
 * {@link ReactiveOAuth2ClientConfiguration}.
 *
 * <p>
 * This {@code Configuration} is imported by {@link EnableWebFluxSecurity}
 *
 * @author Rob Winch
 * @author Alavudin Kuttikkattil
 * @since 5.1
 */
final class ReactiveOAuth2ClientImportSelector implements ImportSelector {

	private static final boolean oauth2ClientPresent;

	static {
		oauth2ClientPresent = ClassUtils.isPresent(
				"org.springframework.security.oauth2.client.registration.ClientRegistration",
				ReactiveOAuth2ClientImportSelector.class.getClassLoader());
	}

	@Override
	public String[] selectImports(AnnotationMetadata importingClassMetadata) {
		if (!oauth2ClientPresent) {
			return new String[0];
		}
		return new String[] {
				"org.springframework.security.config.annotation.web.reactive.ReactiveOAuth2ClientConfiguration" };
	}

}
