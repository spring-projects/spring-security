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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.server.context.SecurityContextServerWebExchangeWebFilter;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.security.Principal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockUser;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * @author Rob Winch
 * @since 5.0
 */
@WithMockUser
@RunWith(SpringRunner.class)
@SecurityTestExecutionListeners
public class SecurityMockServerConfigurersClassAnnotatedTests extends AbstractMockServerConfigurersTests {
	WebTestClient client = WebTestClient
		.bindToController(controller)
		.webFilter(new SecurityContextServerWebExchangeWebFilter())
		.apply(springSecurity())
		.configureClient()
		.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
		.build();

	@Test
	public void wheMockUserWhenClassAnnotatedThenSuccess() {
		client
			.get()
			.exchange()
			.expectStatus().isOk()
			.expectBody(String.class).consumeWith( response -> assertThat(response.getResponseBody()).contains("\"username\":\"user\""));

		Authentication authentication = TestSecurityContextHolder.getContext().getAuthentication();
		controller.assertPrincipalIsEqualTo(authentication);
	}

	@Test
	@WithMockUser("method-user")
	public void withMockUserWhenClassAndMethodAnnotationThenMethodOverrides() {
		client
			.get()
			.exchange()
			.expectStatus().isOk()
			.expectBody(String.class).consumeWith( response -> assertThat(response.getResponseBody()).contains("\"username\":\"method-user\""));

		Authentication authentication = TestSecurityContextHolder.getContext().getAuthentication();
		controller.assertPrincipalIsEqualTo(authentication);
	}

	@Test
	public void withMockUserWhenMutateWithThenMustateWithOverrides() {
		client
			.mutateWith(mockUser("mutateWith-mockUser"))
			.get()
			.exchange()
			.expectStatus().isOk()
			.expectBody(String.class).consumeWith( response -> assertThat(response.getResponseBody()).contains("\"username\":\"mutateWith-mockUser\""));

		Principal principal = controller.removePrincipal();
		assertPrincipalCreatedFromUserDetails(principal, userBuilder.username("mutateWith-mockUser").build());
	}
}
