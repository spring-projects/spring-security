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

package org.springframework.security.config.annotation.authentication.configuration;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.Order;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;

/**
 * Lazily initializes the global authentication with an {@link AuthenticationProvider} if
 * it is not yet configured and there is only a single Bean of that type.
 *
 * @author Rob Winch
 * @since 4.1
 */
@Order(InitializeAuthenticationProviderBeanManagerConfigurer.DEFAULT_ORDER)
class InitializeAuthenticationProviderBeanManagerConfigurer extends GlobalAuthenticationConfigurerAdapter {

	static final int DEFAULT_ORDER = InitializeUserDetailsBeanManagerConfigurer.DEFAULT_ORDER - 100;

	private final ApplicationContext context;

	/**
	 * @param context the ApplicationContext to look up beans.
	 */
	InitializeAuthenticationProviderBeanManagerConfigurer(ApplicationContext context) {
		this.context = context;
	}

	@Override
	public void init(AuthenticationManagerBuilder auth) throws Exception {
		auth.apply(new InitializeAuthenticationProviderManagerConfigurer());
	}

	class InitializeAuthenticationProviderManagerConfigurer extends GlobalAuthenticationConfigurerAdapter {

		private final Log logger = LogFactory.getLog(getClass());

		@Override
		public void configure(AuthenticationManagerBuilder auth) {
			if (auth.isConfigured()) {
				return;
			}
			List<BeanWithName<AuthenticationProvider>> authenticationProviders = getBeansWithName(
					AuthenticationProvider.class);
			if (authenticationProviders.isEmpty()) {
				return;
			}
			else if (authenticationProviders.size() > 1) {
				List<String> beanNames = authenticationProviders.stream().map(BeanWithName::getName).toList();
				this.logger.info(LogMessage.format("Found %s AuthenticationProvider beans, with names %s. "
						+ "Global Authentication Manager will not be configured with AuthenticationProviders. "
						+ "Consider publishing a single AuthenticationProvider bean, or wiring your Providers directly "
						+ "using the DSL.", authenticationProviders.size(), beanNames));
				return;
			}
			var authenticationProvider = authenticationProviders.get(0).getBean();
			var authenticationProviderBeanName = authenticationProviders.get(0).getName();

			auth.authenticationProvider(authenticationProvider);
			this.logger.info(LogMessage.format(
					"Global AuthenticationManager configured with AuthenticationProvider bean with name %s",
					authenticationProviderBeanName));
		}

		/**
		 * @return a bean of the requested class if there's just a single registered
		 * component, null otherwise.
		 */
		private <T> T getBeanOrNull(Class<T> type) {
			String[] beanNames = InitializeAuthenticationProviderBeanManagerConfigurer.this.context
				.getBeanNamesForType(type);
			if (beanNames.length != 1) {
				return null;
			}
			return InitializeAuthenticationProviderBeanManagerConfigurer.this.context.getBean(beanNames[0], type);
		}

		/**
		 * @return a list of beans of the requested class, along with their names. If
		 * there are no registered beans of that type, the list is empty.
		 */
		private <T> List<BeanWithName<T>> getBeansWithName(Class<T> type) {
			List<BeanWithName<T>> beanWithNames = new ArrayList<>();
			String[] beanNames = InitializeAuthenticationProviderBeanManagerConfigurer.this.context
				.getBeanNamesForType(type);
			for (String beanName : beanNames) {
				T bean = InitializeAuthenticationProviderBeanManagerConfigurer.this.context.getBean(beanNames[0], type);
				beanWithNames.add(new BeanWithName<T>(bean, beanName));
			}
			return beanWithNames;
		}

		static class BeanWithName<T> {

			private final T bean;

			private final String name;

			BeanWithName(T bean, String name) {
				this.bean = bean;
				this.name = name;
			}

			T getBean() {
				return this.bean;
			}

			String getName() {
				return this.name;
			}

		}

	}

}
