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

package org.springframework.security.config.annotation.method.configuration;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Fallback;
import org.springframework.context.annotation.ImportAware;
import org.springframework.context.annotation.Role;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.ExpressionBasedAnnotationAttributeFactory;
import org.springframework.security.access.expression.method.ExpressionBasedPostInvocationAdvice;
import org.springframework.security.access.expression.method.ExpressionBasedPreInvocationAdvice;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityMetadataSourceAdvisor;
import org.springframework.security.access.method.AbstractMethodSecurityMetadataSource;
import org.springframework.security.access.method.DelegatingMethodSecurityMetadataSource;
import org.springframework.security.access.prepost.PrePostAdviceReactiveMethodInterceptor;
import org.springframework.security.access.prepost.PrePostAnnotationSecurityMetadataSource;
import org.springframework.security.config.core.GrantedAuthorityDefaults;

/**
 * @author Rob Winch
 * @author Tadaya Tsuyukubo
 * @since 5.0
 */
@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
class ReactiveMethodSecurityConfiguration implements ImportAware {

	private int advisorOrder;

	private GrantedAuthorityDefaults grantedAuthorityDefaults;

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodSecurityMetadataSourceAdvisor methodSecurityInterceptor(AbstractMethodSecurityMetadataSource source,
			ReactiveMethodSecurityConfiguration configuration) {
		MethodSecurityMetadataSourceAdvisor advisor = new MethodSecurityMetadataSourceAdvisor(
				"securityMethodInterceptor", source, "methodMetadataSource");
		advisor.setOrder(configuration.advisorOrder);
		return advisor;
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static DelegatingMethodSecurityMetadataSource methodMetadataSource(
			MethodSecurityExpressionHandler methodSecurityExpressionHandler) {
		ExpressionBasedAnnotationAttributeFactory attributeFactory = new ExpressionBasedAnnotationAttributeFactory(
				methodSecurityExpressionHandler);
		PrePostAnnotationSecurityMetadataSource prePostSource = new PrePostAnnotationSecurityMetadataSource(
				attributeFactory);
		return new DelegatingMethodSecurityMetadataSource(Arrays.asList(prePostSource));
	}

	@Bean
	static PrePostAdviceReactiveMethodInterceptor securityMethodInterceptor(AbstractMethodSecurityMetadataSource source,
			MethodSecurityExpressionHandler handler) {
		ExpressionBasedPostInvocationAdvice postAdvice = new ExpressionBasedPostInvocationAdvice(handler);
		ExpressionBasedPreInvocationAdvice preAdvice = new ExpressionBasedPreInvocationAdvice();
		preAdvice.setExpressionHandler(handler);
		return new PrePostAdviceReactiveMethodInterceptor(source, preAdvice, postAdvice);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	@Fallback
	static DefaultMethodSecurityExpressionHandler methodSecurityExpressionHandler(
			ReactiveMethodSecurityConfiguration configuration) {
		DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
		if (configuration.grantedAuthorityDefaults != null) {
			handler.setDefaultRolePrefix(configuration.grantedAuthorityDefaults.getRolePrefix());
		}
		return handler;
	}

	@Override
	public void setImportMetadata(AnnotationMetadata importMetadata) {
		this.advisorOrder = (int) importMetadata.getAnnotationAttributes(EnableReactiveMethodSecurity.class.getName())
			.get("order");
	}

	@Autowired(required = false)
	void setGrantedAuthorityDefaults(GrantedAuthorityDefaults grantedAuthorityDefaults) {
		this.grantedAuthorityDefaults = grantedAuthorityDefaults;
	}

}
