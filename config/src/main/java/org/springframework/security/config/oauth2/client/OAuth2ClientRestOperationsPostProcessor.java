/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.config.oauth2.client;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * A {@link BeanDefinitionRegistryPostProcessor} that registers a {@link RestOperations}
 * {@link BeanDefinition} with the name {@link OAuth2ClientBeanNames#REST_OPERATIONS}.
 *
 * @author Joe Grandja
 * @since 5.4
 */
public final class OAuth2ClientRestOperationsPostProcessor implements BeanDefinitionRegistryPostProcessor, Ordered {

	@Override
	public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
		if (registry.containsBeanDefinition(OAuth2ClientBeanNames.REST_OPERATIONS)) {
			// Return allowing for bean override
			return;
		}

		AbstractBeanDefinition beanDefinition =
				BeanDefinitionBuilder.genericBeanDefinition(OAuth2ClientRestOperationsFactory.class)
						.getBeanDefinition();
		registry.registerBeanDefinition(OAuth2ClientBeanNames.REST_OPERATIONS, beanDefinition);
	}

	@Override
	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
	}

	@Override
	public int getOrder() {
		return Ordered.LOWEST_PRECEDENCE;
	}

	private static class OAuth2ClientRestOperationsFactory implements FactoryBean<RestOperations> {
		private RestOperations restOperations;

		@Override
		public RestOperations getObject() throws Exception {
			if (this.restOperations == null) {
				this.restOperations = createRestOperations();
			}
			return this.restOperations;
		}

		@Override
		public Class<?> getObjectType() {
			return RestOperations.class;
		}

		@Override
		public boolean isSingleton() {
			return true;
		}

		private RestOperations createRestOperations() {
			RestTemplate restTemplate = new RestTemplate();
			restTemplate.getMessageConverters().add(new OAuth2AccessTokenResponseHttpMessageConverter());
			restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
			return restTemplate;
		}
	}
}
