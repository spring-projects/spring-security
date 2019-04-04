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
package org.springframework.security.test.oauth2.reactive.server;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

import java.security.Principal;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.server.context.SecurityContextServerWebExchangeWebFilter;
import org.springframework.security.web.server.csrf.CsrfWebFilter;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class TestControllers {

	@RestController
	public static class GreetController {
		@RequestMapping("/**")
		public String index(final Principal authentication) {
			return String.format("Hello, %s!", authentication.getName());
		}

		public static WebTestClient.Builder clientBuilder() {
			return WebTestClient.bindToController(new TestControllers.GreetController())
					.webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
					.apply(springSecurity())
					.configureClient()
					.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
		}

		public static WebTestClient client() {
			return clientBuilder().build();
		}
	}

	@RestController
	public static class AuthoritiesController {
		@RequestMapping("/**")
		public String index(final Authentication authentication) {
			return authentication.getAuthorities()
					.stream()
					.map(GrantedAuthority::getAuthority)
					.collect(Collectors.toList())
					.toString();
		}

		public static WebTestClient.Builder clientBuilder() {
			return WebTestClient.bindToController(new TestControllers.AuthoritiesController())
					.webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
					.apply(springSecurity())
					.configureClient()
					.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
		}

		public static WebTestClient client() {
			return clientBuilder().build();
		}
	}

	@RestController
	public static class JwtController {
		@RequestMapping("/**")
		// TODO: investigate why "@AuthenticationPrincipal Jwt token" does not work here
		public String index(final Authentication authentication) {
			final Jwt token = (Jwt) authentication.getPrincipal();
			@SuppressWarnings("unchecked")
			final Collection<String> scopes = (Collection<String>) token.getClaims().get("scope");

			return String.format(
					"Hello, %s! You are sucessfully authenticated and granted with %s scopes using a JavaWebToken.",
					token.getSubject(),
					scopes.toString());
		}

		public static WebTestClient.Builder clientBuilder() {
			return WebTestClient.bindToController(new TestControllers.JwtController())
					.webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
					.apply(springSecurity())
					.configureClient()
					.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
		}

		public static WebTestClient client() {
			return clientBuilder().build();
		}
	}

	@RestController
	public static class AccessTokenController {
		@RequestMapping("/**")
		// TODO: investigate why "@AuthenticationPrincipal Map<String, Object>
		// tokenAttributes" does not work here
		public String index(final Authentication authentication) {
			@SuppressWarnings("unchecked")
			final Map<String, Object> tokenAttributes = (Map<String, Object>) authentication.getPrincipal();
			return String.format(
					"Hello, %s! You are sucessfully authenticated and granted with %s scopes using an OAuth2AccessToken.",
					tokenAttributes.get("username"),
					tokenAttributes.get("scope").toString());
		}

		public static WebTestClient.Builder clientBuilder() {
			return WebTestClient.bindToController(new TestControllers.AccessTokenController())
					.webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
					.apply(springSecurity())
					.configureClient()
					.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
		}

		public static WebTestClient client() {
			return clientBuilder().build();
		}
	}

	@RestController
	public static class OidcIdTokenController {
		@RequestMapping("/**")
		// TODO: investigate why "@AuthenticationPrincipal OidcUser token" does not work
		// here
		public String index(final Authentication authentication) {
			final OidcUser token = (OidcUser) authentication.getPrincipal();
			return String.format(
					"Hello, %s! You are sucessfully authenticated and granted with %s authorities using an OidcId token.",
					token.getName(),
					token.getAuthorities()
							.stream()
							.map(GrantedAuthority::getAuthority)
							.collect(Collectors.toList())
							.toString());
		}

		public static WebTestClient.Builder clientBuilder() {
			return WebTestClient.bindToController(new TestControllers.OidcIdTokenController())
					.webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
					.apply(springSecurity())
					.configureClient()
					.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
		}

		public static WebTestClient client() {
			return clientBuilder().build();
		}
	}
}
