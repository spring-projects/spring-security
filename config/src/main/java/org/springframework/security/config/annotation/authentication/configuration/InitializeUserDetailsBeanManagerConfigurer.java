/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 */

package org.springframework.security.config.annotation.authentication.configuration;

import java.util.Arrays;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

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
 * Lazily initializes the global authentication with a {@link UserDetailsService}
 * if it is not yet configured. Honors {@code @Primary} when multiple
 * {@link UserDetailsService} (or {@link UserDetailsPasswordService}) beans are present.
 * If a single {@link PasswordEncoder} or {@link CompromisedPasswordChecker} bean is
 * available, those are wired as well.
 *
 * @author Rob Winch
 * @author Ngoc Nhan
 * @author You
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

			// If user configured an AuthenticationProvider already, warn and bail
			if (auth.isConfigured()) {
				if (beanNames.length > 0) {
					this.logger.warn(
							"Global AuthenticationManager configured with an AuthenticationProvider bean. "
									+ "UserDetailsService beans will not be used by Spring Security for automatically configuring username/password login. "
									+ "Consider removing the AuthenticationProvider bean or configure DaoAuthenticationProvider manually.");
				}
				return;
			}

			// No UDS beans — nothing to do
			if (beanNames.length == 0) {
				return;
			}

			/*
			 * Try to resolve a single autowire-candidate UDS from the container.
			 * getIfAvailable() returns:
			 *  - the bean if there is exactly one, or
			 *  - the @Primary bean if there are multiple and one is marked primary,
			 *  - otherwise null.
			 */
			UserDetailsService userDetailsService = getAutowireCandidateOrNull(UserDetailsService.class);

			// If still ambiguous and we have multiple beans, keep current (warn + skip)
			if (userDetailsService == null && beanNames.length > 1) {
				this.logger.warn(LogMessage.format(
						"Found %s UserDetailsService beans, with names %s. "
								+ "Global Authentication Manager will not use a UserDetailsService for username/password login. "
								+ "Consider publishing a single (or @Primary) UserDetailsService bean.",
						beanNames.length, Arrays.toString(beanNames)));
				return;
			}

			// If there is exactly one bean and getIfAvailable returned null (shouldn't happen),
			// fall back to retrieving that single bean by name.
			if (userDetailsService == null) {
				userDetailsService = InitializeUserDetailsBeanManagerConfigurer.this.context
						.getBean(beanNames[0], UserDetailsService.class);
			}

			PasswordEncoder passwordEncoder = getBeanIfUnique(PasswordEncoder.class);
			// Honor @Primary for UDPS as well
			UserDetailsPasswordService passwordManager = getAutowireCandidateOrNull(UserDetailsPasswordService.class);
			// Keep "unique only" semantics for optional checker
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

			this.logger.info(LogMessage.format(
					"Global AuthenticationManager configured with UserDetailsService bean (auto-selected)."));
		}

		private <T> T getAutowireCandidateOrNull(Class<T> type) {
			return InitializeUserDetailsBeanManagerConfigurer.this.context.getBeanProvider(type).getIfAvailable();
		}

		private <T> T getBeanIfUnique(Class<T> type) {
			return InitializeUserDetailsBeanManagerConfigurer.this.context.getBeanProvider(type).getIfUnique();
		}
	}

}
