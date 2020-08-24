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

import java.nio.charset.StandardCharsets;
import java.security.Principal;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.config.users.ReactiveAuthenticationTestConfiguration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.reactive.result.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.security.web.reactive.result.view.CsrfRequestDataValueProcessor;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.config.DelegatingWebFluxConfiguration;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.result.view.AbstractView;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(SpringRunner.class)
@SecurityTestExecutionListeners
public class EnableWebFluxSecurityTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	WebFilterChainProxy springSecurityFilterChain;

	@Test
	public void defaultRequiresAuthentication() {
		this.spring.register(Config.class).autowire();
		// @formatter:off
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(this.springSecurityFilterChain)
				.build();
		client.get()
				.uri("/")
				.exchange()
				.expectStatus().isUnauthorized()
				.expectBody().isEmpty();
		// @formatter:on
	}

	// gh-4831
	@Test
	public void defaultMediaAllThenUnAuthorized() {
		this.spring.register(Config.class).autowire();
		// @formatter:off
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(this.springSecurityFilterChain)
				.build();
		client.get()
				.uri("/")
				.accept(MediaType.ALL)
				.exchange()
				.expectStatus().isUnauthorized()
				.expectBody().isEmpty();
		// @formatter:on
	}

	@Test
	public void authenticateWhenBasicThenNoSession() {
		this.spring.register(Config.class).autowire();
		// @formatter:off
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(this.springSecurityFilterChain)
				.build();
		FluxExchangeResult<String> result = client.get()
				.headers((headers) -> headers.setBasicAuth("user", "password"))
				.exchange()
				.expectStatus().isOk()
				.returnResult(String.class);
		// @formatter:on
		result.assertWithDiagnostics(() -> assertThat(result.getResponseCookies().isEmpty()));
	}

	@Test
	public void defaultPopulatesReactorContext() {
		this.spring.register(Config.class).autowire();
		Authentication currentPrincipal = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		WebSessionServerSecurityContextRepository contextRepository = new WebSessionServerSecurityContextRepository();
		SecurityContext context = new SecurityContextImpl(currentPrincipal);
		// @formatter:off
		WebFilter contextRepositoryWebFilter = (exchange, chain) -> contextRepository.save(exchange, context)
				.switchIfEmpty(chain.filter(exchange))
				.flatMap((e) -> chain.filter(exchange));
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(contextRepositoryWebFilter, this.springSecurityFilterChain, writePrincipalWebFilter())
				.build();
		client.get()
				.uri("/")
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class).consumeWith((result) -> assertThat(result.getResponseBody()).isEqualTo(currentPrincipal.getName()));
		// @formatter:on
	}

	private WebFilter writePrincipalWebFilter() {
		// @formatter:off
		return (exchange, chain) -> ReactiveSecurityContextHolder.getContext()
				.map(SecurityContext::getAuthentication)
				.flatMap((principal) -> exchange.getResponse()
						.writeWith(Mono.just(toDataBuffer(principal.getName())))
				);
		// @formatter:on
	}

	@Test
	public void defaultPopulatesReactorContextWhenAuthenticating() {
		this.spring.register(Config.class).autowire();
		// @formatter:off
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(this.springSecurityFilterChain, writePrincipalWebFilter())
				.build();
		client.get()
				.uri("/")
				.headers((headers) -> headers.setBasicAuth("user", "password"))
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class).consumeWith((result) -> assertThat(result.getResponseBody()).isEqualTo("user"));
		// @formatter:on
	}

	@Test
	public void requestDataValueProcessor() {
		this.spring.register(Config.class).autowire();
		ConfigurableApplicationContext context = this.spring.getContext();
		CsrfRequestDataValueProcessor rdvp = context.getBean(AbstractView.REQUEST_DATA_VALUE_PROCESSOR_BEAN_NAME,
				CsrfRequestDataValueProcessor.class);
		assertThat(rdvp).isNotNull();
	}

	@Test
	public void passwordEncoderBeanIsUsed() {
		this.spring.register(CustomPasswordEncoderConfig.class).autowire();
		// @formatter:off
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(this.springSecurityFilterChain, writePrincipalWebFilter())
				.build();
		client.get().uri("/").headers((headers) -> headers.setBasicAuth("user", "password"))
				.exchange().expectStatus().isOk()
				.expectBody(String.class)
				.consumeWith((result) -> assertThat(result.getResponseBody()).isEqualTo("user"));
		// @formatter:on
	}

	@Test
	public void passwordUpdateManagerUsed() {
		this.spring.register(MapReactiveUserDetailsServiceConfig.class).autowire();
		// @formatter:off
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(this.springSecurityFilterChain)
				.build();
		client.get()
				.uri("/")
				.headers((h) -> h.setBasicAuth("user", "password"))
				.exchange()
				.expectStatus().isOk();
		// @formatter:on
		ReactiveUserDetailsService users = this.spring.getContext().getBean(ReactiveUserDetailsService.class);
		assertThat(users.findByUsername("user").block().getPassword()).startsWith("{bcrypt}");
	}

	@Test
	public void formLoginWorks() {
		this.spring.register(Config.class).autowire();
		// @formatter:off
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(this.springSecurityFilterChain, writePrincipalWebFilter())
				.build();
		// @formatter:on
		MultiValueMap<String, String> data = new LinkedMultiValueMap<>();
		data.add("username", "user");
		data.add("password", "password");
		// @formatter:off
		client.mutateWith(csrf())
				.post()
				.uri("/login")
				.body(BodyInserters.fromFormData(data))
				.exchange()
				.expectStatus().is3xxRedirection()
				.expectHeader().valueMatches("Location", "/");
		// @formatter:on
	}

	@Test
	public void multiWorks() {
		this.spring.register(MultiSecurityHttpConfig.class).autowire();
		// @formatter:off
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(this.springSecurityFilterChain)
				.build();
		client.get()
				.uri("/api/test")
				.exchange()
				.expectStatus().isUnauthorized()
				.expectBody().isEmpty();
		client.get()
				.uri("/test")
				.exchange()
				.expectStatus().isOk();
		// @formatter:on
	}

	@Test
	@WithMockUser
	public void authenticationPrincipalArgumentResolverWhenSpelThenWorks() {
		this.spring.register(AuthenticationPrincipalConfig.class).autowire();
		// @formatter:off
		WebTestClient client = WebTestClient
				.bindToApplicationContext(this.spring.getContext())
				.build();
		client.get()
				.uri("/spel")
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo("user");
		// @formatter:on
	}

	private static DataBuffer toDataBuffer(String body) {
		DataBuffer buffer = new DefaultDataBufferFactory().allocateBuffer();
		buffer.write(body.getBytes(StandardCharsets.UTF_8));
		return buffer;
	}

	@Test
	public void enableWebFluxSecurityWhenNoConfigurationAnnotationThenBeanProxyingEnabled() {
		this.spring.register(BeanProxyEnabledByDefaultConfig.class).autowire();
		Child childBean = this.spring.getContext().getBean(Child.class);
		Parent parentBean = this.spring.getContext().getBean(Parent.class);
		assertThat(parentBean.getChild()).isSameAs(childBean);
	}

	@Test
	public void enableWebFluxSecurityWhenProxyBeanMethodsFalseThenBeanProxyingDisabled() {
		this.spring.register(BeanProxyDisabledConfig.class).autowire();
		Child childBean = this.spring.getContext().getBean(Child.class);
		Parent parentBean = this.spring.getContext().getBean(Parent.class);
		assertThat(parentBean.getChild()).isNotSameAs(childBean);
	}

	@Test
	// gh-8596
	public void resolveAuthenticationPrincipalArgumentResolverFirstDoesNotCauseBeanCurrentlyInCreationException() {
		this.spring.register(EnableWebFluxSecurityConfiguration.class, ReactiveAuthenticationTestConfiguration.class,
				DelegatingWebFluxConfiguration.class).autowire();
	}

	@EnableWebFluxSecurity
	@Import(ReactiveAuthenticationTestConfiguration.class)
	static class Config {

	}

	@EnableWebFluxSecurity
	static class CustomPasswordEncoderConfig {

		@Bean
		ReactiveUserDetailsService userDetailsService(PasswordEncoder encoder) {
			return new MapReactiveUserDetailsService(
					User.withUsername("user").password(encoder.encode("password")).roles("USER").build());
		}

		@Bean
		static PasswordEncoder passwordEncoder() {
			return new BCryptPasswordEncoder();
		}

	}

	@EnableWebFluxSecurity
	static class MapReactiveUserDetailsServiceConfig {

		@Bean
		MapReactiveUserDetailsService userDetailsService() {
			// @formatter:off
			return new MapReactiveUserDetailsService(User.withUsername("user")
					.password("{noop}password")
					.roles("USER")
					.build()
			// @formatter:on
			);
		}

	}

	@EnableWebFluxSecurity
	@Import(ReactiveAuthenticationTestConfiguration.class)
	static class MultiSecurityHttpConfig {

		@Order(Ordered.HIGHEST_PRECEDENCE)
		@Bean
		SecurityWebFilterChain apiHttpSecurity(ServerHttpSecurity http) {
			http.securityMatcher(new PathPatternParserServerWebExchangeMatcher("/api/**")).authorizeExchange()
					.anyExchange().denyAll();
			return http.build();
		}

		@Bean
		SecurityWebFilterChain httpSecurity(ServerHttpSecurity http) {
			return http.build();
		}

	}

	@EnableWebFluxSecurity
	@EnableWebFlux
	@Import(ReactiveAuthenticationTestConfiguration.class)
	static class AuthenticationPrincipalConfig {

		@Bean
		PrincipalBean principalBean() {
			return new PrincipalBean();
		}

		static class PrincipalBean {

			public String username(UserDetails user) {
				return user.getUsername();
			}

		}

		@RestController
		static class AuthenticationPrincipalResolver {

			@GetMapping("/spel")
			String username(@AuthenticationPrincipal(expression = "@principalBean.username(#this)") String username) {
				return username;
			}

		}

	}

	@EnableWebFluxSecurity
	@Import(ReactiveAuthenticationTestConfiguration.class)
	static class BeanProxyEnabledByDefaultConfig {

		@Bean
		Child child() {
			return new Child();
		}

		@Bean
		Parent parent() {
			return new Parent(child());
		}

	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebFluxSecurity
	@Import(ReactiveAuthenticationTestConfiguration.class)
	static class BeanProxyDisabledConfig {

		@Bean
		Child child() {
			return new Child();
		}

		@Bean
		Parent parent() {
			return new Parent(child());
		}

	}

	static class Parent {

		private Child child;

		Parent(Child child) {
			this.child = child;
		}

		Child getChild() {
			return this.child;
		}

	}

	static class Child {

		Child() {
		}

	}

	@EnableWebFluxSecurity
	@Configuration(proxyBeanMethods = false)
	static class EnableWebFluxSecurityConfiguration {

		/**
		 * It is necessary to Autowire AuthenticationPrincipalArgumentResolver because it
		 * triggers eager loading of AuthenticationPrincipalArgumentResolver bean which
		 * causes BeanCurrentlyInCreationException
		 */
		@Autowired
		AuthenticationPrincipalArgumentResolver resolver;

	}

}
