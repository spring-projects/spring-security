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

package org.springframework.security.config.annotation.authentication.configuration;

import java.util.Arrays;

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
			String[] beanNames = InitializeAuthenticationProviderBeanManagerConfigurer.this.context
				.getBeanNamesForType(AuthenticationProvider.class);
			if (beanNames.length == 0) {
				return;
			}
			else if (beanNames.length > 1) {
				this.logger.info(LogMessage.format("Found %s AuthenticationProvider beans, with names %s. "
						+ "Global Authentication Manager will not be configured with AuthenticationProviders. "
						+ "Consider publishing a single AuthenticationProvider bean, or wiring your Providers directly "
						+ "using the DSL.", beanNames.length, Arrays.toString(beanNames)));
				return;
			}
			AuthenticationProvider authenticationProvider = InitializeAuthenticationProviderBeanManagerConfigurer.this.context
				.getBean(beanNames[0], AuthenticationProvider.class);
			auth.authenticationProvider(authenticationProvider);
			this.logger.info(LogMessage.format(
					"Global AuthenticationManager configured with AuthenticationProvider bean with name %s",
					beanNames[0]));
		}

	}

}
