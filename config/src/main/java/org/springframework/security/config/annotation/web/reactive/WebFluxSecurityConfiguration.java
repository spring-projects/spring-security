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

package org.springframework.security.config.annotation.web.reactive;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.crypto.RsaKeyConversionServicePostProcessor;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.reactive.result.view.CsrfRequestDataValueProcessor;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.security.web.server.WebFilterChainProxy.DefaultWebFilterChainDecorator;
import org.springframework.security.web.server.WebFilterChainProxy.WebFilterChainDecorator;
import org.springframework.security.web.server.firewall.ServerExchangeRejectedHandler;
import org.springframework.security.web.server.firewall.ServerWebExchangeFirewall;
import org.springframework.util.ClassUtils;
import org.springframework.util.ObjectUtils;
import org.springframework.web.reactive.result.view.AbstractView;

/**
 * @author Rob Winch
 * @since 5.0
 */
@Configuration(proxyBeanMethods = false)
class WebFluxSecurityConfiguration {

	public static final int WEB_FILTER_CHAIN_FILTER_ORDER = 0 - 100;

	private static final String BEAN_NAME_PREFIX = "org.springframework.security.config.annotation.web.reactive.WebFluxSecurityConfiguration.";

	private static final String SPRING_SECURITY_WEBFILTERCHAINFILTER_BEAN_NAME = BEAN_NAME_PREFIX
			+ "WebFilterChainFilter";

	public static final String REACTIVE_CLIENT_REGISTRATION_REPOSITORY_CLASSNAME = "org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository";

	private static final boolean isOAuth2Present;

	private List<SecurityWebFilterChain> securityWebFilterChains;

	private ObjectPostProcessor<WebFilterChainDecorator> postProcessor = ObjectPostProcessor.identity();

	static {
		isOAuth2Present = ClassUtils.isPresent(REACTIVE_CLIENT_REGISTRATION_REPOSITORY_CLASSNAME,
				WebFluxSecurityConfiguration.class.getClassLoader());
	}

	@Autowired
	ApplicationContext context;

	@Autowired(required = false)
	void setSecurityWebFilterChains(List<SecurityWebFilterChain> securityWebFilterChains) {
		this.securityWebFilterChains = securityWebFilterChains;
	}

	@Autowired(required = false)
	void setFilterChainPostProcessor(ObjectPostProcessor<WebFilterChainDecorator> postProcessor) {
		this.postProcessor = postProcessor;
	}

	@Bean(SPRING_SECURITY_WEBFILTERCHAINFILTER_BEAN_NAME)
	@Order(WEB_FILTER_CHAIN_FILTER_ORDER)
	WebFilterChainProxy springSecurityWebFilterChainFilter(ObjectProvider<ServerWebExchangeFirewall> firewall,
			ObjectProvider<ServerExchangeRejectedHandler> rejectedHandler) {
		WebFilterChainProxy proxy = new WebFilterChainProxy(getSecurityWebFilterChains());
		WebFilterChainDecorator decorator = this.postProcessor.postProcess(new DefaultWebFilterChainDecorator());
		proxy.setFilterChainDecorator(decorator);
		firewall.ifUnique(proxy::setFirewall);
		rejectedHandler.ifUnique(proxy::setExchangeRejectedHandler);
		return proxy;
	}

	@Bean(name = AbstractView.REQUEST_DATA_VALUE_PROCESSOR_BEAN_NAME)
	CsrfRequestDataValueProcessor requestDataValueProcessor() {
		return new CsrfRequestDataValueProcessor();
	}

	@Bean
	static BeanFactoryPostProcessor conversionServicePostProcessor() {
		return new RsaKeyConversionServicePostProcessor();
	}

	private List<SecurityWebFilterChain> getSecurityWebFilterChains() {
		List<SecurityWebFilterChain> result = this.securityWebFilterChains;
		if (ObjectUtils.isEmpty(result)) {
			return Arrays.asList(springSecurityFilterChain());
		}
		return result;
	}

	private SecurityWebFilterChain springSecurityFilterChain() {
		ServerHttpSecurity http = this.context.getBean(ServerHttpSecurity.class);
		return springSecurityFilterChain(http);
	}

	/**
	 * The default {@link ServerHttpSecurity} configuration.
	 * @param http
	 * @return
	 */
	private SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
		http.authorizeExchange().anyExchange().authenticated();
		if (isOAuth2Present && OAuth2ClasspathGuard.shouldConfigure(this.context)) {
			OAuth2ClasspathGuard.configure(this.context, http);
		}
		else {
			http.httpBasic();
			http.formLogin();
		}
		SecurityWebFilterChain result = http.build();
		return result;
	}

	private static class OAuth2ClasspathGuard {

		static void configure(ApplicationContext context, ServerHttpSecurity http) {
			http.oauth2Login();
			http.oauth2Client();
		}

		static boolean shouldConfigure(ApplicationContext context) {
			ClassLoader loader = context.getClassLoader();
			Class<?> reactiveClientRegistrationRepositoryClass = ClassUtils
				.resolveClassName(REACTIVE_CLIENT_REGISTRATION_REPOSITORY_CLASSNAME, loader);
			return context.getBeanNamesForType(reactiveClientRegistrationRepositoryClass).length == 1;
		}

	}

}
