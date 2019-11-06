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

package org.springframework.security.config.annotation.web.reactive;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.expression.BeanFactoryResolver;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsPasswordService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.reactive.result.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.security.web.reactive.result.method.annotation.CurrentSecurityContextArgumentResolver;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.result.method.annotation.ArgumentResolverConfigurer;

/**
 * @author Rob Winch
 * @author Dan Zheng
 * @since 5.0
 */
@Configuration(proxyBeanMethods = false)
class ServerHttpSecurityConfiguration {
	private static final String BEAN_NAME_PREFIX = "org.springframework.security.config.annotation.web.reactive.HttpSecurityConfiguration.";
	private static final String HTTPSECURITY_BEAN_NAME = BEAN_NAME_PREFIX + "httpSecurity";

	private ReactiveAdapterRegistry adapterRegistry = new ReactiveAdapterRegistry();

	private ReactiveAuthenticationManager authenticationManager;

	private ReactiveUserDetailsService reactiveUserDetailsService;

	private PasswordEncoder passwordEncoder;

	private ReactiveUserDetailsPasswordService userDetailsPasswordService;

	@Autowired(required = false)
	private BeanFactory beanFactory;

	@Autowired(required = false)
	void setAdapterRegistry(ReactiveAdapterRegistry adapterRegistry) {
		this.adapterRegistry = adapterRegistry;
	}

	@Autowired(required = false)
	void setAuthenticationManager(ReactiveAuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Autowired(required = false)
	void setReactiveUserDetailsService(ReactiveUserDetailsService reactiveUserDetailsService) {
		this.reactiveUserDetailsService = reactiveUserDetailsService;
	}

	@Autowired(required = false)
	void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Autowired(required = false)
	void setUserDetailsPasswordService(ReactiveUserDetailsPasswordService userDetailsPasswordService) {
		this.userDetailsPasswordService = userDetailsPasswordService;
	}

	@Bean
	public WebFluxConfigurer authenticationPrincipalArgumentResolverConfigurer(
			AuthenticationPrincipalArgumentResolver authenticationPrincipalArgumentResolver) {
		return new WebFluxConfigurer() {
			@Override
			public void configureArgumentResolvers(ArgumentResolverConfigurer configurer) {
				configurer.addCustomResolver(authenticationPrincipalArgumentResolver);
			}
		};
	}

	@Bean
	public AuthenticationPrincipalArgumentResolver authenticationPrincipalArgumentResolver() {
		AuthenticationPrincipalArgumentResolver resolver = new AuthenticationPrincipalArgumentResolver(
			this.adapterRegistry);
		if (this.beanFactory != null) {
			resolver.setBeanResolver(new BeanFactoryResolver(this.beanFactory));
		}
		return resolver;
	}

	@Bean
	public CurrentSecurityContextArgumentResolver reactiveCurrentSecurityContextArgumentResolver() {
		CurrentSecurityContextArgumentResolver resolver = new CurrentSecurityContextArgumentResolver(
				this.adapterRegistry);
		if (this.beanFactory != null) {
			resolver.setBeanResolver(new BeanFactoryResolver(this.beanFactory));
		}
		return resolver;
	}

	@Bean(HTTPSECURITY_BEAN_NAME)
	@Scope("prototype")
	public ServerHttpSecurity httpSecurity() {
		ContextAwareServerHttpSecurity http = new ContextAwareServerHttpSecurity();
		return http
			.authenticationManager(authenticationManager())
			.headers().and()
			.logout().and();
	}

	private ReactiveAuthenticationManager authenticationManager() {
		if (this.authenticationManager != null) {
			return this.authenticationManager;
		}
		if (this.reactiveUserDetailsService != null) {
			UserDetailsRepositoryReactiveAuthenticationManager manager =
				new UserDetailsRepositoryReactiveAuthenticationManager(this.reactiveUserDetailsService);
			if (this.passwordEncoder != null) {
				manager.setPasswordEncoder(this.passwordEncoder);
			}
			manager.setUserDetailsPasswordService(this.userDetailsPasswordService);
			return manager;
		}
		return null;
	}

	private static class ContextAwareServerHttpSecurity extends ServerHttpSecurity implements
			ApplicationContextAware {
		@Override
		public void setApplicationContext(ApplicationContext applicationContext)
				throws BeansException {
			super.setApplicationContext(applicationContext);
		}
	}
}
