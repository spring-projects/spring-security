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

package org.springframework.security.test.web.reactive.server;

import java.util.Map;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Tests for {@link SecurityMockServerRequestBuilders}.
 *
 * @author Rob Winch
 */
public class SecurityMockServerRequestBuildersTests {

	@Test
	public void formLoginWhenDefaultsThenAuthenticatedSessionEstablished() {
		try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(
				DefaultSecurityConfig.class)) {
			WebTestClient client = webTestClient(context);
			FluxExchangeResult<byte[]> loginResult = SecurityMockServerRequestBuilders.formLogin()
				.exchange(client)
				.expectStatus()
				.is3xxRedirection()
				.returnResult(byte[].class);
			String session = sessionId(loginResult);
			client.get()
				.uri("/resource")
				.cookie("SESSION", session)
				.exchange()
				.expectStatus()
				.isOk()
				.expectBody(String.class)
				.isEqualTo("user");
		}
	}

	@Test
	public void logoutWhenDefaultsThenSessionInvalidated() {
		try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(
				DefaultSecurityConfig.class)) {
			WebTestClient client = webTestClient(context);
			FluxExchangeResult<byte[]> loginResult = SecurityMockServerRequestBuilders.formLogin()
				.exchange(client)
				.expectStatus()
				.is3xxRedirection()
				.returnResult(byte[].class);
			String session = sessionId(loginResult);
			WebTestClient authenticatedClient = client.mutate().defaultCookie("SESSION", session).build();
			SecurityMockServerRequestBuilders.logout().exchange(authenticatedClient).expectStatus().is3xxRedirection();
			client.get().uri("/resource").cookie("SESSION", session).exchange().expectStatus().is3xxRedirection();
		}
	}

	@Test
	public void formLoginWhenCustomLoginUrlThenAuthenticatedSessionEstablished() {
		try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(
				CustomLoginLogoutSecurityConfig.class)) {
			WebTestClient client = webTestClient(context);
			FluxExchangeResult<byte[]> loginResult = SecurityMockServerRequestBuilders.formLogin()
				.loginProcessingUrl("/custom-{segment}", "login")
				.exchange(client)
				.expectStatus()
				.is3xxRedirection()
				.returnResult(byte[].class);
			String session = sessionId(loginResult);
			client.get()
				.uri("/resource")
				.cookie("SESSION", session)
				.exchange()
				.expectStatus()
				.isOk()
				.expectBody(String.class)
				.isEqualTo("user");
		}
	}

	@Test
	public void logoutWhenCustomLogoutUrlThenSessionInvalidated() {
		try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(
				CustomLoginLogoutSecurityConfig.class)) {
			WebTestClient client = webTestClient(context);
			FluxExchangeResult<byte[]> loginResult = SecurityMockServerRequestBuilders.formLogin("/custom-login")
				.exchange(client)
				.expectStatus()
				.is3xxRedirection()
				.returnResult(byte[].class);
			String session = sessionId(loginResult);
			WebTestClient authenticatedClient = client.mutate().defaultCookie("SESSION", session).build();
			SecurityMockServerRequestBuilders.logout()
				.logoutUrl("/custom-{segment}", "logout")
				.exchange(authenticatedClient)
				.expectStatus()
				.is3xxRedirection();
			client.get().uri("/resource").cookie("SESSION", session).exchange().expectStatus().is3xxRedirection();
		}
	}

	@Test
	public void formLoginWhenCustomThenUsesParametersAndAccept() {
		RequestCaptureController controller = new RequestCaptureController();
		WebTestClient client = WebTestClient.bindToController(controller).configureClient().build();
		SecurityMockServerRequestBuilders.formLogin()
			.loginProcessingUrl("/uri-login/{var1}/{var2}", "val1", "val2")
			.user("username", "admin")
			.password("password", "secret")
			.acceptMediaType(MediaType.APPLICATION_JSON)
			.exchange(client)
			.expectStatus()
			.isOk();
		assertThat(controller.path).isEqualTo("/uri-login/val1/val2");
		assertThat(controller.params.get("username")).isEqualTo("admin");
		assertThat(controller.params.get("password")).isEqualTo("secret");
		assertThat(controller.accept).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
	}

	@Test
	public void formLoginWhenWebTestClientIsNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> SecurityMockServerRequestBuilders.formLogin().exchange(null));
	}

	@Test
	public void logoutWhenWebTestClientIsNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> SecurityMockServerRequestBuilders.logout().exchange(null));
	}

	private static WebTestClient webTestClient(AnnotationConfigApplicationContext context) {
		return WebTestClient.bindToApplicationContext(context).apply(springSecurity()).configureClient().build();
	}

	private static String sessionId(FluxExchangeResult<?> result) {
		ResponseCookie sessionCookie = result.getResponseCookies().getFirst("SESSION");
		assertThat(sessionCookie).isNotNull();
		return sessionCookie.getValue();
	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class DefaultSecurityConfig {

		@Bean
		SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
			return http
				.authorizeExchange(
						(authorize) -> authorize.pathMatchers("/resource").authenticated().anyExchange().permitAll())
				.formLogin(withDefaults())
				.logout(withDefaults())
				.build();
		}

		@Bean
		ReactiveUserDetailsService userDetailsService() {
			return new MapReactiveUserDetailsService(
					User.withUsername("user").password("{noop}password").roles("USER").build());
		}

		@Bean
		ResourceController resourceController() {
			return new ResourceController();
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class CustomLoginLogoutSecurityConfig {

		@Bean
		SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
			return http
				.authorizeExchange(
						(authorize) -> authorize.pathMatchers("/resource").authenticated().anyExchange().permitAll())
				.formLogin((formLogin) -> formLogin.loginPage("/custom-login"))
				.logout((logout) -> logout.logoutUrl("/custom-logout"))
				.build();
		}

		@Bean
		ReactiveUserDetailsService userDetailsService() {
			return new MapReactiveUserDetailsService(
					User.withUsername("user").password("{noop}password").roles("USER").build());
		}

		@Bean
		ResourceController resourceController() {
			return new ResourceController();
		}

	}

	@RestController
	static class ResourceController {

		@GetMapping("/resource")
		String resource(Authentication authentication) {
			return authentication.getName();
		}

	}

	@RestController
	static class RequestCaptureController {

		volatile String path;

		volatile Map<String, String> params;

		volatile String accept;

		@PostMapping("/**")
		Mono<String> capture(ServerWebExchange exchange) {
			this.path = exchange.getRequest().getPath().pathWithinApplication().value();
			this.accept = exchange.getRequest().getHeaders().getFirst(HttpHeaders.ACCEPT);
			return exchange.getFormData().map((formData) -> {
				this.params = formData.toSingleValueMap();
				return "ok";
			});
		}

	}

}
