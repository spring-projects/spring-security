/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.annotation.method.configuration;

import java.util.Arrays;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.context.annotation.Role;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.expression.method.DefaultReactiveMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.ExpressionBasedAnnotationAttributeFactory;
import org.springframework.security.access.expression.method.ExpressionBasedReactivePostInvocationAuthorizationAdvice;
import org.springframework.security.access.expression.method.ExpressionBasedReactivePreInvocationAuthorizationAdvice;
import org.springframework.security.access.expression.method.ReactiveMethodSecurityExpressionHandler;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityMetadataSourceAdvisor;
import org.springframework.security.access.method.AbstractMethodSecurityMetadataSource;
import org.springframework.security.access.method.DelegatingMethodSecurityMetadataSource;
import org.springframework.security.access.prepost.PrePostAnnotationSecurityMetadataSource;
import org.springframework.security.access.prepost.ReactivePrePostAdviceMethodInterceptor;

/**
 * @author Rob Winch
 * @since 5.0
 */
@Configuration
class ReactiveMethodSecurityConfiguration implements ImportAware {
	private int advisorOrder;

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	public MethodSecurityMetadataSourceAdvisor methodSecurityInterceptor(AbstractMethodSecurityMetadataSource source) throws Exception {
		MethodSecurityMetadataSourceAdvisor advisor = new MethodSecurityMetadataSourceAdvisor(
			"securityMethodInterceptor", source, "methodMetadataSource");
		advisor.setOrder(advisorOrder);
		return advisor;
	}

	@Bean
	public DelegatingMethodSecurityMetadataSource methodMetadataSource(ReactiveMethodSecurityExpressionHandler handler) {
		ExpressionBasedAnnotationAttributeFactory attributeFactory =
				new ExpressionBasedAnnotationAttributeFactory(handler);
		PrePostAnnotationSecurityMetadataSource prePostSource =
				new PrePostAnnotationSecurityMetadataSource(attributeFactory);

		return new DelegatingMethodSecurityMetadataSource(Arrays.asList(prePostSource));
	}

	@Bean
	public ReactivePrePostAdviceMethodInterceptor securityMethodInterceptor(AbstractMethodSecurityMetadataSource source, ReactiveMethodSecurityExpressionHandler handler) {
		ExpressionBasedReactivePostInvocationAuthorizationAdvice postAdvice =
				new ExpressionBasedReactivePostInvocationAuthorizationAdvice(handler);
		ExpressionBasedReactivePreInvocationAuthorizationAdvice preAdvice =
				new ExpressionBasedReactivePreInvocationAuthorizationAdvice(handler);

		return new ReactivePrePostAdviceMethodInterceptor(source, preAdvice, postAdvice);
	}

	@Bean
	public DefaultReactiveMethodSecurityExpressionHandler methodSecurityExpressionHandler() {
		return new DefaultReactiveMethodSecurityExpressionHandler();
	}

	@Override
	public void setImportMetadata(AnnotationMetadata importMetadata) {
		this.advisorOrder = (int) importMetadata.getAnnotationAttributes(EnableReactiveMethodSecurity.class.getName()).get("order");
	}
}
