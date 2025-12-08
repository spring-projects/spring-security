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

package org.springframework.security.config.annotation.web.reactive;

import java.lang.reflect.Modifier;
import java.util.Map;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.expression.BeanFactoryResolver;
import org.springframework.core.MethodParameter;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.core.ResolvableType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.authentication.password.ReactiveCompromisedPasswordChecker;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.core.userdetails.ReactiveUserDetailsPasswordService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.reactive.result.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.security.web.reactive.result.method.annotation.CurrentSecurityContextArgumentResolver;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.result.method.annotation.ArgumentResolverConfigurer;

import static org.springframework.security.config.Customizer.withDefaults;

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

	private ReactiveCompromisedPasswordChecker compromisedPasswordChecker;

	private ObjectPostProcessor<ReactiveAuthenticationManager> postProcessor = ObjectPostProcessor.identity();

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

	@Autowired(required = false)
	void setAuthenticationManagerPostProcessor(
			Map<String, ObjectPostProcessor<ReactiveAuthenticationManager>> postProcessors) {
		if (postProcessors.size() == 1) {
			this.postProcessor = postProcessors.values().iterator().next();
		}
		this.postProcessor = postProcessors.get("reactiveAuthenticationManagerPostProcessor");
	}

	@Autowired(required = false)
	void setCompromisedPasswordChecker(ReactiveCompromisedPasswordChecker compromisedPasswordChecker) {
		this.compromisedPasswordChecker = compromisedPasswordChecker;
	}

	@Bean
	static WebFluxConfigurer authenticationPrincipalArgumentResolverConfigurer(
			ObjectProvider<AuthenticationPrincipalArgumentResolver> authenticationPrincipalArgumentResolver,
			ObjectProvider<CurrentSecurityContextArgumentResolver> currentSecurityContextArgumentResolvers) {
		return new WebFluxConfigurer() {

			@Override
			public void configureArgumentResolvers(ArgumentResolverConfigurer configurer) {
				configurer.addCustomResolver(authenticationPrincipalArgumentResolver.getObject(),
						currentSecurityContextArgumentResolvers.getObject());
			}

		};
	}

	@Bean
	AuthenticationPrincipalArgumentResolver authenticationPrincipalArgumentResolver(
			ObjectProvider<AnnotationTemplateExpressionDefaults> templateDefaults) {
		AuthenticationPrincipalArgumentResolver resolver = new AuthenticationPrincipalArgumentResolver(
				this.adapterRegistry);
		if (this.beanFactory != null) {
			resolver.setBeanResolver(new BeanFactoryResolver(this.beanFactory));
		}
		templateDefaults.ifAvailable(resolver::setTemplateDefaults);
		return resolver;
	}

	@Bean
	CurrentSecurityContextArgumentResolver reactiveCurrentSecurityContextArgumentResolver(
			ObjectProvider<AnnotationTemplateExpressionDefaults> templateDefaults) {
		CurrentSecurityContextArgumentResolver resolver = new CurrentSecurityContextArgumentResolver(
				this.adapterRegistry);
		if (this.beanFactory != null) {
			resolver.setBeanResolver(new BeanFactoryResolver(this.beanFactory));
		}
		templateDefaults.ifAvailable(resolver::setTemplateDefaults);
		return resolver;
	}

	@Bean(HTTPSECURITY_BEAN_NAME)
	@Scope("prototype")
	ServerHttpSecurity httpSecurity(ApplicationContext context) {
		ServerHttpSecurity http = httpSecurity();
		applyServerHttpSecurityCustomizers(context, http);
		applyTopLevelBeanCustomizers(context, http);
		return http;
	}

	/**
	 * Applies all {@code Customizer<ServerHttpSecurity>} Beans to
	 * {@link ServerHttpSecurity}.
	 * @param context the {@link ApplicationContext}
	 * @param http the {@link ServerHttpSecurity}
	 * @throws Exception
	 */
	private void applyServerHttpSecurityCustomizers(ApplicationContext context, ServerHttpSecurity http) {
		ResolvableType httpSecurityCustomizerType = ResolvableType.forClassWithGenerics(Customizer.class,
				ServerHttpSecurity.class);
		ObjectProvider<Customizer<ServerHttpSecurity>> customizerProvider = context
			.getBeanProvider(httpSecurityCustomizerType);

		// @formatter:off
		customizerProvider.orderedStream().forEach((customizer) ->
			customizer.customize(http)
		);
		// @formatter:on
	}

	/**
	 * Applies all {@link Customizer} Beans to top level {@link ServerHttpSecurity}
	 * method.
	 *
	 * For each public, non-static method in ServerHttpSecurity that accepts a Customizer
	 * <ul>
	 * <li>Use the {@link MethodParameter} (this preserves generics) to resolve all Beans
	 * for that type</li>
	 * <li>For each {@link Customizer} Bean invoke the {@link java.lang.reflect.Method}
	 * with the {@link Customizer} Bean as the argument</li>
	 * </ul>
	 * @param context the {@link ApplicationContext}
	 * @param http the {@link ServerHttpSecurity}
	 * @throws Exception
	 */
	private void applyTopLevelBeanCustomizers(ApplicationContext context, ServerHttpSecurity http) {
		ReflectionUtils.MethodFilter isCustomizerMethod = (method) -> {
			if (Modifier.isStatic(method.getModifiers())) {
				return false;
			}
			if (!Modifier.isPublic(method.getModifiers())) {
				return false;
			}
			if (!method.canAccess(http)) {
				return false;
			}
			if (method.getParameterCount() != 1) {
				return false;
			}
			if (method.getParameterTypes()[0] == Customizer.class) {
				return true;
			}
			return false;
		};
		ReflectionUtils.MethodCallback invokeWithEachCustomizerBean = (customizerMethod) -> {

			MethodParameter customizerParameter = new MethodParameter(customizerMethod, 0);
			ResolvableType customizerType = ResolvableType.forMethodParameter(customizerParameter);
			ObjectProvider<?> customizerProvider = context.getBeanProvider(customizerType);

			// @formatter:off
			customizerProvider.orderedStream().forEach((customizer) ->
					ReflectionUtils.invokeMethod(customizerMethod, http, customizer)
			);
			// @formatter:on

		};
		ReflectionUtils.doWithMethods(ServerHttpSecurity.class, invokeWithEachCustomizerBean, isCustomizerMethod);
	}

	ServerHttpSecurity httpSecurity() {
		ContextAwareServerHttpSecurity http = new ContextAwareServerHttpSecurity();
		// @formatter:off
		return http.authenticationManager(authenticationManager())
			.headers(withDefaults())
			.logout(withDefaults());
		// @formatter:on
	}

	private ReactiveAuthenticationManager authenticationManager() {
		if (this.authenticationManager != null) {
			return this.authenticationManager;
		}
		if (this.reactiveUserDetailsService != null) {
			UserDetailsRepositoryReactiveAuthenticationManager manager = new UserDetailsRepositoryReactiveAuthenticationManager(
					this.reactiveUserDetailsService);
			if (this.passwordEncoder != null) {
				manager.setPasswordEncoder(this.passwordEncoder);
			}
			if (this.userDetailsPasswordService != null) {
				manager.setUserDetailsPasswordService(this.userDetailsPasswordService);
			}
			manager.setCompromisedPasswordChecker(this.compromisedPasswordChecker);
			return this.postProcessor.postProcess(manager);
		}
		return null;
	}

	private static class ContextAwareServerHttpSecurity extends ServerHttpSecurity implements ApplicationContextAware {

		@Override
		public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
			super.setApplicationContext(applicationContext);
		}

	}

}
