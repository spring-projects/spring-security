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

package org.springframework.security.config.annotation.authorization;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;

/**
 * Uses {@link EnableMultiFactorAuthentication} to configure a
 * {@link DefaultAuthorizationManagerFactory}.
 *
 * @author Rob Winch
 * @since 7.0
 * @see EnableMultiFactorAuthentication
 */
class MultiFactorAuthenticationSelector implements ImportSelector {

	@Override
	public String[] selectImports(AnnotationMetadata metadata) {
		Map<String, Object> multiFactorAuthenticationAttrs = metadata
			.getAnnotationAttributes(EnableMultiFactorAuthentication.class.getName());
		String[] authorities = (String[]) multiFactorAuthenticationAttrs.getOrDefault("authorities", new String[0]);
		List<String> imports = new ArrayList<>(2);
		if (authorities.length > 0) {
			imports.add(AuthorizationManagerFactoryConfiguration.class.getName());
		}
		imports.add(EnableMfaFiltersConfiguration.class.getName());
		return imports.toArray(new String[imports.size()]);
	}

}
