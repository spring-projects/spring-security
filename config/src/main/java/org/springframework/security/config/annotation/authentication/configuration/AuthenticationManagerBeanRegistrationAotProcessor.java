/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.authentication.configuration;

import java.util.Set;

import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.aot.generate.GenerationContext;
import org.springframework.aot.hint.ProxyHints;
import org.springframework.beans.factory.aot.BeanRegistrationAotContribution;
import org.springframework.beans.factory.aot.BeanRegistrationAotProcessor;
import org.springframework.beans.factory.aot.BeanRegistrationCode;
import org.springframework.beans.factory.support.RegisteredBean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.util.ClassUtils;

/**
 * AOT {@code BeanRegistrationAotProcessor} that detects beans that implement
 * {@link AuthenticationManager} creates the required proxy hints.
 *
 * @author Marcus da Coregio
 * @since 6.0.1
 * @see AuthenticationConfiguration#getAuthenticationManager()
 */
class AuthenticationManagerBeanRegistrationAotProcessor implements BeanRegistrationAotProcessor {

	@Override
	public BeanRegistrationAotContribution processAheadOfTime(RegisteredBean registeredBean) {
		Class<?> beanClass = registeredBean.getBeanClass();
		Set<Class<?>> allInterfacesForClass = ClassUtils.getAllInterfacesForClassAsSet(beanClass);
		if (allInterfacesForClass.contains(AuthenticationManager.class)) {
			return new AuthenticationManagerBeanRegistrationAotContribution();
		}
		return null;
	}

	private static class AuthenticationManagerBeanRegistrationAotContribution
			implements BeanRegistrationAotContribution {

		@Override
		public void applyTo(GenerationContext generationContext, BeanRegistrationCode beanRegistrationCode) {
			ProxyHints proxyHints = generationContext.getRuntimeHints().proxies();
			proxyHints.registerJdkProxy(AopProxyUtils.completeJdkProxyInterfaces(AuthenticationManager.class));
		}

	}

}
