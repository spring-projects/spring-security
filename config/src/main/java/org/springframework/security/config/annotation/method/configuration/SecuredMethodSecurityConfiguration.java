/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.config.annotation.method.configuration;

import org.aopalliance.intercept.MethodInterceptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

/**
 * {@link Configuration} for enabling {@link Secured} Spring Security Method Security.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.6
 * @see EnableMethodSecurity
 */
@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
final class SecuredMethodSecurityConfiguration {

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	MethodInterceptor securedAuthorizationMethodInterceptor() {
		AuthorizationManagerBeforeMethodInterceptor interceptor = AuthorizationManagerBeforeMethodInterceptor.secured();
		interceptor.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
		return interceptor;
	}

	@Autowired(required = false)
	void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

}
