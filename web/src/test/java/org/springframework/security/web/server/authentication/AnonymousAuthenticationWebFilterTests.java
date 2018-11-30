/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.server.authentication;

import java.util.UUID;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;

/**
 * @author Ankur Pathak
 * @since 5.2.0
 */
@RunWith(MockitoJUnitRunner.class)
public class AnonymousAuthenticationWebFilterTests {

	@Test
	public void anonymousAuthenticationFilterWorking() {

		WebTestClient client = WebTestClientBuilder.bindToControllerAndWebFilters(HttpMeController.class,
				new AnonymousAuthenticationWebFilter(UUID.randomUUID().toString()))
				.build();

		client.get()
				.uri("/me")
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo("anonymousUser");
	}

	@RestController
	@RequestMapping("/me")
	public static class HttpMeController {
		@GetMapping
		public Mono<String> me(ServerWebExchange exchange) {
			return ReactiveSecurityContextHolder
					.getContext()
					.map(SecurityContext::getAuthentication)
					.map(Authentication::getPrincipal)
					.ofType(String.class);
		}
	}
}
