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

import java.util.Map;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ImportAware;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authorization.AuthorizationManagerFactories;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;

/**
 * Uses {@link EnableGlobalMultiFactorAuthentication} to configure a
 * {@link DefaultAuthorizationManagerFactory}.
 *
 * @author Rob Winch
 * @since 7.0
 * @see EnableGlobalMultiFactorAuthentication
 */
class AuthorizationManagerFactoryConfiguration implements ImportAware {

	private String[] authorities;

	@Bean
	DefaultAuthorizationManagerFactory authorizationManagerFactory(ObjectProvider<RoleHierarchy> roleHierarchy) {
		AuthorizationManagerFactories.AdditionalRequiredFactorsBuilder<Object> builder = AuthorizationManagerFactories
			.multiFactor()
			.requireFactors(this.authorities);
		return builder.build();
	}

	@Override
	public void setImportMetadata(AnnotationMetadata importMetadata) {
		Map<String, Object> multiFactorAuthenticationAttrs = importMetadata
			.getAnnotationAttributes(EnableGlobalMultiFactorAuthentication.class.getName());

		this.authorities = (String[]) multiFactorAuthenticationAttrs.getOrDefault("authorities", new String[0]);
	}

}
