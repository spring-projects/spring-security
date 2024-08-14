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

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import org.springframework.aop.Advisor;
import org.springframework.aop.Pointcut;
import org.springframework.aop.PointcutAdvisor;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.Ordered;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.authorization.method.AuthorizationAdvisor;

class MethodSecurityAdvisorRegistrar implements ImportBeanDefinitionRegistrar {

	@Override
	public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry) {
		registerAsAdvisor("preFilterAuthorization", registry);
		registerAsAdvisor("preAuthorizeAuthorization", registry);
		registerAsAdvisor("postFilterAuthorization", registry);
		registerAsAdvisor("postAuthorizeAuthorization", registry);
		registerAsAdvisor("securedAuthorization", registry);
		registerAsAdvisor("jsr250Authorization", registry);
		registerAsAdvisor("authorizeReturnObject", registry);
	}

	private void registerAsAdvisor(String prefix, BeanDefinitionRegistry registry) {
		String advisorName = prefix + "Advisor";
		if (registry.containsBeanDefinition(advisorName)) {
			return;
		}
		String interceptorName = prefix + "MethodInterceptor";
		if (!registry.containsBeanDefinition(interceptorName)) {
			return;
		}
		BeanDefinition definition = registry.getBeanDefinition(interceptorName);
		if (!(definition instanceof RootBeanDefinition)) {
			return;
		}
		BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(AdvisorWrapper.class);
		builder.setFactoryMethod("of");
		builder.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
		builder.addConstructorArgReference(interceptorName);
		RootBeanDefinition advisor = (RootBeanDefinition) builder.getBeanDefinition();
		advisor.setTargetType(Advisor.class);
		registry.registerBeanDefinition(advisorName, advisor);
	}

	public static final class AdvisorWrapper
			implements PointcutAdvisor, MethodInterceptor, Ordered, AopInfrastructureBean {

		private final AuthorizationAdvisor advisor;

		private AdvisorWrapper(AuthorizationAdvisor advisor) {
			this.advisor = advisor;
		}

		public static AdvisorWrapper of(AuthorizationAdvisor advisor) {
			return new AdvisorWrapper(advisor);
		}

		@Override
		public Advice getAdvice() {
			return this.advisor.getAdvice();
		}

		@Override
		public Pointcut getPointcut() {
			return this.advisor.getPointcut();
		}

		@Override
		public int getOrder() {
			return this.advisor.getOrder();
		}

		@Nullable
		@Override
		public Object invoke(@NotNull MethodInvocation invocation) throws Throwable {
			return this.advisor.invoke(invocation);
		}

	}

}
