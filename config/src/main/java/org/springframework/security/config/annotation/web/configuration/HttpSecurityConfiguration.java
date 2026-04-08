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

package org.springframework.security.config.annotation.web.configuration;

import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.core.MethodParameter;
import org.springframework.core.ResolvableType;
import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.lang.Contract;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.JdbcUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.security.config.web.PathPatternRequestMatcherBuilderFactoryBean;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.function.ThrowingSupplier;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * {@link Configuration} that exposes the {@link HttpSecurity} bean.
 *
 * @author Eleftheria Stein
 * @author Jinwoo Bae
 * @author Ngoc Nhan
 * @since 5.4
 */
@Configuration(proxyBeanMethods = false)
class HttpSecurityConfiguration {

	private static final String BEAN_NAME_PREFIX = "org.springframework.security.config.annotation.web.configuration.HttpSecurityConfiguration.";

	private static final String HTTPSECURITY_BEAN_NAME = BEAN_NAME_PREFIX + "httpSecurity";

	private ObjectPostProcessor<Object> objectPostProcessor;

	private AuthenticationConfiguration authenticationConfiguration;

	private ApplicationContext context;

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	private ContentNegotiationStrategy contentNegotiationStrategy = new HeaderContentNegotiationStrategy();

	@Autowired
	void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		this.objectPostProcessor = objectPostProcessor;
	}

	@Autowired
	void setAuthenticationConfiguration(AuthenticationConfiguration authenticationConfiguration) {
		this.authenticationConfiguration = authenticationConfiguration;
	}

	@Autowired
	void setApplicationContext(ApplicationContext context) {
		this.context = context;
	}

	@Autowired(required = false)
	void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	@Autowired(required = false)
	void setContentNegotiationStrategy(ContentNegotiationStrategy contentNegotiationStrategy) {
		this.contentNegotiationStrategy = contentNegotiationStrategy;
	}

	@Bean(HTTPSECURITY_BEAN_NAME)
	@Scope("prototype")
	HttpSecurity httpSecurity() {
		LazyPasswordEncoder passwordEncoder = new LazyPasswordEncoder(this.context);
		AuthenticationManagerBuilder authenticationBuilder = new DefaultPasswordEncoderAuthenticationManagerBuilder(
				this.objectPostProcessor, passwordEncoder);
		authenticationBuilder.parentAuthenticationManager(authenticationManager());
		authenticationBuilder.authenticationEventPublisher(getAuthenticationEventPublisher());
		HttpSecurity http = new HttpSecurity(this.objectPostProcessor, authenticationBuilder, createSharedObjects());
		WebAsyncManagerIntegrationFilter webAsyncManagerIntegrationFilter = new WebAsyncManagerIntegrationFilter();
		webAsyncManagerIntegrationFilter.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
		// @formatter:off
		http
			.csrf(withDefaults())
			.addFilter(webAsyncManagerIntegrationFilter)
			.exceptionHandling(withDefaults())
			.headers(withDefaults())
			.sessionManagement(withDefaults())
			.securityContext(withDefaults())
			.requestCache(withDefaults())
			.anonymous(withDefaults())
			.servletApi(withDefaults())
			.with(new DefaultLoginPageConfigurer<>());
		http.logout(withDefaults());
		// @formatter:on
		applyCorsIfAvailable(http);
		applyDefaultConfigurers(http);
		applyHttpSecurityCustomizers(this.context, http);
		applyTopLevelCustomizers(this.context, http);
		return http;
	}

	private void applyCorsIfAvailable(HttpSecurity http) {
		if (this.context.getBeanNamesForType(UrlBasedCorsConfigurationSource.class).length > 0) {
			http.cors(withDefaults());
		}
	}

	private AuthenticationManager authenticationManager() {
		return this.authenticationConfiguration.getAuthenticationManager();
	}

	private AuthenticationEventPublisher getAuthenticationEventPublisher() {
		if (this.context.getBeanNamesForType(AuthenticationEventPublisher.class).length > 0) {
			return this.context.getBean(AuthenticationEventPublisher.class);
		}
		return this.objectPostProcessor.postProcess(new DefaultAuthenticationEventPublisher());
	}

	private void applyDefaultConfigurers(HttpSecurity http) {
		ClassLoader classLoader = this.context.getClassLoader();
		List<AbstractHttpConfigurer> defaultHttpConfigurers = SpringFactoriesLoader
			.loadFactories(AbstractHttpConfigurer.class, classLoader);
		for (AbstractHttpConfigurer configurer : defaultHttpConfigurers) {
			http.with(configurer);
		}
	}

	/**
	 * Applies all {@code Customizer<HttpSecurity>} Bean instances to the
	 * {@link HttpSecurity} instance.
	 * @param applicationContext the {@link ApplicationContext} to lookup Bean instances
	 * @param http the {@link HttpSecurity} to apply the Beans to.
	 */
	private void applyHttpSecurityCustomizers(ApplicationContext applicationContext, HttpSecurity http) {
		ResolvableType httpSecurityCustomizerType = ResolvableType.forClassWithGenerics(Customizer.class,
				HttpSecurity.class);
		ObjectProvider<Customizer<HttpSecurity>> customizerProvider = this.context
			.getBeanProvider(httpSecurityCustomizerType);

		// @formatter:off
		customizerProvider.orderedStream().forEach((customizer) ->
				customizer.customize(http)
		);
		// @formatter:on
	}

	/**
	 * Applies all {@link Customizer} Beans to {@link HttpSecurity}. For each public,
	 * non-static method in HttpSecurity that accepts a Customizer
	 * <ul>
	 * <li>Use the {@link MethodParameter} (this preserves generics) to resolve all Beans
	 * for that type</li>
	 * <li>For each {@link Customizer} Bean invoke the {@link java.lang.reflect.Method}
	 * with the {@link Customizer} Bean as the argument</li>
	 * </ul>
	 * @param context the {@link ApplicationContext}
	 * @param http the {@link HttpSecurity} @
	 */
	private void applyTopLevelCustomizers(ApplicationContext context, HttpSecurity http) {
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
		ReflectionUtils.doWithMethods(HttpSecurity.class, invokeWithEachCustomizerBean, isCustomizerMethod);
	}

	private Map<Class<?>, Object> createSharedObjects() {
		Map<Class<?>, Object> sharedObjects = new HashMap<>();
		sharedObjects.put(ApplicationContext.class, this.context);
		sharedObjects.put(ContentNegotiationStrategy.class, this.contentNegotiationStrategy);
		sharedObjects.put(PathPatternRequestMatcher.Builder.class, constructRequestMatcherBuilder(this.context));
		return sharedObjects;
	}

	private PathPatternRequestMatcher.Builder constructRequestMatcherBuilder(ApplicationContext context) {
		PathPatternRequestMatcherBuilderFactoryBean requestMatcherBuilder = new PathPatternRequestMatcherBuilderFactoryBean();
		requestMatcherBuilder.setApplicationContext(context);
		requestMatcherBuilder.setBeanFactory(context.getAutowireCapableBeanFactory());
		requestMatcherBuilder.setBeanName(requestMatcherBuilder.toString());
		return ThrowingSupplier.of(requestMatcherBuilder::getObject).get();
	}

	static class DefaultPasswordEncoderAuthenticationManagerBuilder extends AuthenticationManagerBuilder {

		private PasswordEncoder defaultPasswordEncoder;

		/**
		 * Creates a new instance
		 * @param objectPostProcessor the {@link ObjectPostProcessor} instance to use.
		 */
		DefaultPasswordEncoderAuthenticationManagerBuilder(ObjectPostProcessor<Object> objectPostProcessor,
				PasswordEncoder defaultPasswordEncoder) {
			super(objectPostProcessor);
			this.defaultPasswordEncoder = defaultPasswordEncoder;
		}

		@Override
		public InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> inMemoryAuthentication() {
			return super.inMemoryAuthentication().passwordEncoder(this.defaultPasswordEncoder);
		}

		@Override
		public JdbcUserDetailsManagerConfigurer<AuthenticationManagerBuilder> jdbcAuthentication() {
			return super.jdbcAuthentication().passwordEncoder(this.defaultPasswordEncoder);
		}

		@Override
		public <T extends UserDetailsService> DaoAuthenticationConfigurer<AuthenticationManagerBuilder, T> userDetailsService(
				T userDetailsService) {
			return super.userDetailsService(userDetailsService).passwordEncoder(this.defaultPasswordEncoder);
		}

	}

	static class LazyPasswordEncoder implements PasswordEncoder {

		private ApplicationContext applicationContext;

		private PasswordEncoder passwordEncoder;

		LazyPasswordEncoder(ApplicationContext applicationContext) {
			this.applicationContext = applicationContext;
		}

		@Override
		@Contract("!null -> !null; null -> null")
		public String encode(CharSequence rawPassword) {
			return getPasswordEncoder().encode(rawPassword);
		}

		@Override
		public boolean matches(CharSequence rawPassword, String encodedPassword) {
			return getPasswordEncoder().matches(rawPassword, encodedPassword);
		}

		@Override
		public boolean upgradeEncoding(String encodedPassword) {
			return getPasswordEncoder().upgradeEncoding(encodedPassword);
		}

		private PasswordEncoder getPasswordEncoder() {
			if (this.passwordEncoder != null) {
				return this.passwordEncoder;
			}
			this.passwordEncoder = this.applicationContext.getBeanProvider(PasswordEncoder.class)
				.getIfUnique(PasswordEncoderFactories::createDelegatingPasswordEncoder);
			return this.passwordEncoder;
		}

		@Override
		public String toString() {
			return getPasswordEncoder().toString();
		}

	}

}
