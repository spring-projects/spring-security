/*
 * Copyright 2002-2017 the original author or authors.
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

import java.util.concurrent.ForkJoinPool;

import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.server.context.SecurityContextServerWebExchangeWebFilter;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(SpringRunner.class)
@SecurityTestExecutionListeners
public class SecurityMockServerConfigurersAnnotatedTests extends AbstractMockServerConfigurersTests {

	WebTestClient client = WebTestClient.bindToController(this.controller)
			.webFilter(new SecurityContextServerWebExchangeWebFilter())
			.apply(SecurityMockServerConfigurers.springSecurity()).configureClient()
			.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE).build();

	@Test
	@WithMockUser
	public void withMockUserWhenOnMethodThenSuccess() {
		this.client.get().exchange().expectStatus().isOk();

		Authentication authentication = TestSecurityContextHolder.getContext().getAuthentication();
		this.controller.assertPrincipalIsEqualTo(authentication);
	}

	@Test
	@WithMockUser
	public void withMockUserWhenGlobalMockPrincipalThenOverridesAnnotation() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("authentication", "secret",
				"ROLE_USER");
		this.client = WebTestClient.bindToController(this.controller)
				.webFilter(new SecurityContextServerWebExchangeWebFilter())
				.apply(SecurityMockServerConfigurers.springSecurity())
				.apply(SecurityMockServerConfigurers.mockAuthentication(authentication)).configureClient()
				.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE).build();

		this.client.get().exchange().expectStatus().isOk();

		this.controller.assertPrincipalIsEqualTo(authentication);
	}

	@Test
	@WithMockUser
	public void withMockUserWhenMutateWithMockPrincipalThenOverridesAnnotation() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("authentication", "secret",
				"ROLE_USER");
		this.client.mutateWith(SecurityMockServerConfigurers.mockAuthentication(authentication)).get().exchange()
				.expectStatus().isOk();

		this.controller.assertPrincipalIsEqualTo(authentication);
	}

	@Test
	@WithMockUser
	public void withMockUserWhenMutateWithMockPrincipalAndNoMutateThenOverridesAnnotationAndUsesAnnotation() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("authentication", "secret",
				"ROLE_USER");
		this.client.mutateWith(SecurityMockServerConfigurers.mockAuthentication(authentication)).get().exchange()
				.expectStatus().isOk();

		this.controller.assertPrincipalIsEqualTo(authentication);

		this.client.get().exchange().expectStatus().isOk();

		assertPrincipalCreatedFromUserDetails(this.controller.removePrincipal(), this.userBuilder.build());
	}

	@Test
	@WithMockUser
	public void withMockUserWhenOnMethodAndRequestIsExecutedOnDifferentThreadThenSuccess() {
		Authentication authentication = TestSecurityContextHolder.getContext().getAuthentication();
		ForkJoinPool.commonPool().submit(() -> this.client.get().exchange().expectStatus().isOk()).join();

		this.controller.assertPrincipalIsEqualTo(authentication);
	}

	@Test
	@WithMockUser
	public void withMockUserAndWithCallOnSeparateThreadWhenMutateWithMockPrincipalAndNoMutateThenOverridesAnnotationAndUsesAnnotation() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("authentication", "secret",
				"ROLE_USER");

		ForkJoinPool.commonPool()
				.submit(() -> this.client.mutateWith(SecurityMockServerConfigurers.mockAuthentication(authentication))
						.get().exchange().expectStatus().isOk())
				.join();

		this.controller.assertPrincipalIsEqualTo(authentication);

		ForkJoinPool.commonPool().submit(() -> this.client.get().exchange().expectStatus().isOk()).join();

		assertPrincipalCreatedFromUserDetails(this.controller.removePrincipal(), this.userBuilder.build());
	}

}
