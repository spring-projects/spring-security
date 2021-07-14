/*
 * Copyright 2002-2021 the original author or authors.
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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authorization.method.PostAuthorizeReactiveAuthorizationManager;
import org.springframework.security.authorization.method.PostFilterAuthorizationAfterReactiveMethodInterceptor;
import org.springframework.security.authorization.method.PreAuthorizeReactiveAuthorizationManager;
import org.springframework.security.authorization.method.PreFilterAuthorizationBeforeReactiveMethodInterceptor;
import org.springframework.security.authorization.method.ReactiveAuthorizationManagerAfterMethodInterceptor;
import org.springframework.security.authorization.method.ReactiveAuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.config.core.GrantedAuthorityDefaults;

/**
 * @author Rob Winch
 * @author Tadaya Tsuyukubo
 * @author Evgeniy Cheban
 * @since 5.0
 */
@Configuration(proxyBeanMethods = false)
class ReactiveMethodSecurityConfiguration {

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	PreFilterAuthorizationBeforeReactiveMethodInterceptor preFilterInterceptor(
			MethodSecurityExpressionHandler expressionHandler) {
		PreFilterAuthorizationBeforeReactiveMethodInterceptor preFilter = new PreFilterAuthorizationBeforeReactiveMethodInterceptor();
		preFilter.setExpressionHandler(expressionHandler);
		return preFilter;
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	ReactiveAuthorizationManagerBeforeMethodInterceptor preAuthorizeInterceptor(
			MethodSecurityExpressionHandler expressionHandler) {
		PreAuthorizeReactiveAuthorizationManager authorizationManager = new PreAuthorizeReactiveAuthorizationManager();
		authorizationManager.setExpressionHandler(expressionHandler);
		return ReactiveAuthorizationManagerBeforeMethodInterceptor.preAuthorize(authorizationManager);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	PostFilterAuthorizationAfterReactiveMethodInterceptor postFilterInterceptor(
			MethodSecurityExpressionHandler expressionHandler) {
		PostFilterAuthorizationAfterReactiveMethodInterceptor postFilter = new PostFilterAuthorizationAfterReactiveMethodInterceptor();
		postFilter.setExpressionHandler(expressionHandler);
		return postFilter;
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	ReactiveAuthorizationManagerAfterMethodInterceptor postAuthorizeInterceptor(
			MethodSecurityExpressionHandler expressionHandler) {
		PostAuthorizeReactiveAuthorizationManager authorizationManager = new PostAuthorizeReactiveAuthorizationManager();
		authorizationManager.setExpressionHandler(expressionHandler);
		return ReactiveAuthorizationManagerAfterMethodInterceptor.postAuthorize(authorizationManager);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	DefaultMethodSecurityExpressionHandler methodSecurityExpressionHandler(
			@Autowired(required = false) GrantedAuthorityDefaults grantedAuthorityDefaults) {
		DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
		if (grantedAuthorityDefaults != null) {
			handler.setDefaultRolePrefix(grantedAuthorityDefaults.getRolePrefix());
		}
		return handler;
	}

}
