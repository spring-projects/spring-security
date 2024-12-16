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

package org.springframework.security.config.annotation.method.configuration;

import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.aot.hint.SecurityHintsRegistrar;
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.security.data.aot.hint.AuthorizeReturnObjectDataHintsRegistrar;

@Configuration(proxyBeanMethods = false)
final class AuthorizationProxyDataConfiguration implements AopInfrastructureBean {

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static SecurityHintsRegistrar authorizeReturnObjectDataHintsRegistrar(AuthorizationProxyFactory proxyFactory) {
		return new AuthorizeReturnObjectDataHintsRegistrar(proxyFactory);
	}

}
