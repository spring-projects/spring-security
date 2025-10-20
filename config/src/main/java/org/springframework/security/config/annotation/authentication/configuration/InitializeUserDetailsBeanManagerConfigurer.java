/*
 * Copyright 2004-present the original author or authors.
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

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Lazily initializes the global authentication with a {@link UserDetailsService}. If
 * multiple beans of that type exist, the container's autowire rules are used to select a
 * single candidate (e.g. {@code @Primary}). If no single candidate can be resolved, the
 * configurer logs a warning and does not auto-wire. Optionally wires a
 * {@link PasswordEncoder}, {@link UserDetailsPasswordService}, and
 * {@link CompromisedPasswordChecker} when available.
 *
 * @author Rob Winch
 * @author Ngoc Nhan
 * @since 4.1
 */
@Order(InitializeUserDetailsBeanManagerConfigurer.DEFAULT_ORDER)
class InitializeUserDetailsBeanManagerConfigurer extends GlobalAuthenticationConfigurerAdapter {

	static final int DEFAULT_ORDER = Ordered.LOWEST_PRECEDENCE - 5000;

	private final ApplicationContext context;

	InitializeUserDetailsBeanManagerConfigurer(ApplicationContext context) {
		this.context = context;
	}

	@Override
	public void init(AuthenticationManagerBuilder auth) {
		auth.apply(new InitializeUserDetailsManagerConfigurer());
	}

	class InitializeUserDetailsManagerConfigurer extends GlobalAuthenticationConfigurerAdapter {

		private final Log logger = LogFactory.getLog(getClass());

		@Override
		public void configure(AuthenticationManagerBuilder auth) {
			String[] beanNames = InitializeUserDetailsBeanManagerConfigurer.this.context
				.getBeanNamesForType(UserDetailsService.class);

			if (beanNames.length == 0) {
				return;
			}

			if (auth.isConfigured()) {
				this.logger.warn("Global AuthenticationManager configured with an AuthenticationProvider bean. "
						+ "UserDetailsService beans will not be used by Spring Security for automatically configuring username/password login. "
						+ "Consider removing the AuthenticationProvider bean. "
						+ "Alternatively, consider using the UserDetailsService in a manually instantiated DaoAuthenticationProvider. "
						+ "If the current configuration is intentional, to turn off this warning, "
						+ "increase the logging level of 'org.springframework.security.config.annotation.authentication.configuration.InitializeUserDetailsBeanManagerConfigurer' to ERROR");
				return;
			}

			UserDetailsService userDetailsService = getBeanIfUnique(UserDetailsService.class);
			if (userDetailsService == null) {
				this.logger.warn(LogMessage.format("Found %s UserDetailsService beans, with names %s. "
						+ "Global Authentication Manager will not use a UserDetailsService for username/password login. "
						+ "Consider publishing a single (or primary) UserDetailsService bean.", beanNames.length,
						Arrays.toString(beanNames)));
				return;
			}

			PasswordEncoder passwordEncoder = getBeanIfUnique(PasswordEncoder.class);
			UserDetailsPasswordService passwordManager = getAutowireCandidateOrNull(UserDetailsPasswordService.class);
			CompromisedPasswordChecker passwordChecker = getBeanIfUnique(CompromisedPasswordChecker.class);

			DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
			if (passwordEncoder != null) {
				provider.setPasswordEncoder(passwordEncoder);
			}
			if (passwordManager != null) {
				provider.setUserDetailsPasswordService(passwordManager);
			}
			if (passwordChecker != null) {
				provider.setCompromisedPasswordChecker(passwordChecker);
			}
			provider.afterPropertiesSet();
			auth.authenticationProvider(provider);

			String selectedName = resolveBeanName(beanNames, userDetailsService);
			this.logger.info(LogMessage.format(
					"Global AuthenticationManager configured with UserDetailsService bean with name %s", selectedName));
		}

		/**
		 * Resolve a single autowire candidate for the given type (honors
		 * {@code @Primary}). Returns {@code null} if ambiguous or not present.
		 */
		private <T> T getAutowireCandidateOrNull(Class<T> type) {
			try {
				return InitializeUserDetailsBeanManagerConfigurer.this.context.getBeanProvider(type).getIfAvailable();
			}
			catch (BeansException ex) {
				return null;
			}
		}

		/**
		 * Return a bean of the requested class if there's exactly one registered
		 * component; {@code null} otherwise.
		 */
		private <T> T getBeanIfUnique(Class<T> type) {
			return InitializeUserDetailsBeanManagerConfigurer.this.context.getBeanProvider(type).getIfUnique();
		}

		private String resolveBeanName(String[] candidates, Object instance) {
			for (String name : candidates) {
				try {
					Object bean = InitializeUserDetailsBeanManagerConfigurer.this.context.getBean(name);
					if (bean == instance) {
						return name;
					}
				}
				catch (BeansException ignored) {
				}
			}
			return instance.getClass().getName();
		}

	}

}
