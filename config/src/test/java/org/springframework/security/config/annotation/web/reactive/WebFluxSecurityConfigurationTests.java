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

import java.util.Collections;

import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import reactor.core.publisher.Mono;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.config.users.ReactiveAuthenticationTestConfiguration;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.security.web.server.firewall.HttpStatusExchangeRejectedHandler;
import org.springframework.security.web.server.firewall.ServerExchangeRejectedHandler;
import org.springframework.security.web.server.firewall.ServerWebExchangeFirewall;
import org.springframework.web.server.handler.DefaultWebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link WebFluxSecurityConfiguration}.
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension.class)
public class WebFluxSecurityConfigurationTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	public void loadConfigWhenReactiveUserDetailsServiceConfiguredThenWebFilterChainProxyExists() {
		this.spring
			.register(ServerHttpSecurityConfiguration.class, ReactiveAuthenticationTestConfiguration.class,
					WebFluxSecurityConfiguration.class)
			.autowire();
		WebFilterChainProxy webFilterChainProxy = this.spring.getContext().getBean(WebFilterChainProxy.class);
		assertThat(webFilterChainProxy).isNotNull();
	}

	@Test
	void loadConfigWhenDefaultThenFirewalled() throws Exception {
		this.spring
			.register(ServerHttpSecurityConfiguration.class, ReactiveAuthenticationTestConfiguration.class,
					WebFluxSecurityConfiguration.class)
			.autowire();
		WebFilterChainProxy webFilterChainProxy = this.spring.getContext().getBean(WebFilterChainProxy.class);
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/;/").build());
		DefaultWebFilterChain chain = emptyChain();
		webFilterChainProxy.filter(exchange, chain).block();
		assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
	}

	@Test
	void loadConfigWhenCustomRejectedHandler() throws Exception {
		this.spring
			.register(ServerHttpSecurityConfiguration.class, ReactiveAuthenticationTestConfiguration.class,
					WebFluxSecurityConfiguration.class, CustomServerExchangeRejectedHandlerConfig.class)
			.autowire();
		WebFilterChainProxy webFilterChainProxy = this.spring.getContext().getBean(WebFilterChainProxy.class);
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/;/").build());
		DefaultWebFilterChain chain = emptyChain();
		webFilterChainProxy.filter(exchange, chain).block();
		assertThat(exchange.getResponse().getStatusCode())
			.isEqualTo(CustomServerExchangeRejectedHandlerConfig.EXPECTED_STATUS);
	}

	@Test
	void loadConfigWhenFirewallBeanThenCustomized() throws Exception {
		this.spring
			.register(ServerHttpSecurityConfiguration.class, ReactiveAuthenticationTestConfiguration.class,
					WebFluxSecurityConfiguration.class, NoOpFirewallConfig.class)
			.autowire();
		WebFilterChainProxy webFilterChainProxy = this.spring.getContext().getBean(WebFilterChainProxy.class);
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/;/").build());
		DefaultWebFilterChain chain = emptyChain();
		webFilterChainProxy.filter(exchange, chain).block();
		assertThat(exchange.getResponse().getStatusCode()).isNotEqualTo(HttpStatus.BAD_REQUEST);
	}

	@Test
	public void loadConfigWhenBeanProxyingEnabledAndSubclassThenWebFilterChainProxyExists() {
		this.spring
			.register(ServerHttpSecurityConfiguration.class, ReactiveAuthenticationTestConfiguration.class,
					WebFluxSecurityConfigurationTests.SubclassConfig.class)
			.autowire();
		WebFilterChainProxy webFilterChainProxy = this.spring.getContext().getBean(WebFilterChainProxy.class);
		assertThat(webFilterChainProxy).isNotNull();
	}

	private static @NotNull DefaultWebFilterChain emptyChain() {
		return new DefaultWebFilterChain((webExchange) -> Mono.empty(), Collections.emptyList());
	}

	@Configuration
	static class NoOpFirewallConfig {

		@Bean
		ServerWebExchangeFirewall noOpFirewall() {
			return ServerWebExchangeFirewall.INSECURE_NOOP;
		}

	}

	@Configuration
	static class CustomServerExchangeRejectedHandlerConfig {

		static HttpStatus EXPECTED_STATUS = HttpStatus.I_AM_A_TEAPOT;

		@Bean
		ServerExchangeRejectedHandler rejectedHandler() {
			return new HttpStatusExchangeRejectedHandler(EXPECTED_STATUS);
		}

	}

	@Configuration
	static class SubclassConfig extends WebFluxSecurityConfiguration {

	}

}
