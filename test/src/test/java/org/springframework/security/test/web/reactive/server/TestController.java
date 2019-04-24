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
package org.springframework.security.test.web.reactive.server;

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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
@RestController
public class TestController {

	@GetMapping("/greet")
	public String greet(final Principal authentication) {
		return String.format("Hello, %s!", authentication.getName());
	}

	@GetMapping("/authorities")
	public String authentication(final Authentication authentication) {
		return authentication.getAuthorities()
				.stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.toList())
				.toString();
	}

	@GetMapping("/jwt")
	// TODO: investigate why "@AuthenticationPrincipal Jwt token" does not work here
	public String jwt(final Authentication authentication) {
		final Jwt token = (Jwt) authentication.getPrincipal();
		@SuppressWarnings("unchecked")
		final Collection<String> scopes = (Collection<String>) token.getClaims().get("scope");

		return String.format(
				"Hello, %s! You are sucessfully authenticated and granted with %s scopes using a Jwt.",
				token.getSubject(),
				scopes.toString());
	}

	public static WebTestClient.Builder clientBuilder() {
		return WebTestClient.bindToController(new TestController())
				.webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
				.apply(springSecurity())
				.configureClient()
				.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
	}

	public static WebTestClient client() {
		return (WebTestClient) clientBuilder().build();
	}
}
