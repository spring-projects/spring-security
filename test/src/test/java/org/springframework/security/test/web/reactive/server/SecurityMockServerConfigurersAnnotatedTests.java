/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.test.web.reactive.server;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.security.Principal;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockPrincipal;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(SpringRunner.class)
@SecurityTestExecutionListeners
public class SecurityMockServerConfigurersAnnotatedTests extends AbstractMockServerConfigurersTests {

	WebTestClient client = WebTestClient
		.bindToController(controller)
		.apply(springSecurity())
		.configureClient()
		.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
		.build();

	@Test
	@WithMockUser
	public void withMockUserWhenOnMethodThenSuccess() {
		client
			.get()
			.exchange()
			.expectStatus().isOk();

		Authentication authentication = TestSecurityContextHolder.getContext().getAuthentication();
		controller.assertPrincipalIsEqualTo(authentication);
	}

	@Test
	@WithMockUser
	public void withMockUserWhenGlobalMockPrincipalThenOverridesAnnotation() {
		Principal principal = () -> "principal";
		client = WebTestClient
			.bindToController(controller)
			.apply(springSecurity())
			.apply(mockPrincipal(principal))
			.configureClient()
			.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
			.build();

		client
			.get()
			.exchange()
			.expectStatus().isOk();

		controller.assertPrincipalIsEqualTo(principal);
	}

	@Test
	@WithMockUser
	public void withMockUserWhenMutateWithMockPrincipalThenOverridesAnnotation() {
		Principal principal = () -> "principal";
		client
			.mutateWith(mockPrincipal(principal))
			.get()
			.exchange()
			.expectStatus().isOk();

		controller.assertPrincipalIsEqualTo(principal);
	}

	@Test
	@WithMockUser
	public void withMockUserWhenMutateWithMockPrincipalAndNoMutateThenOverridesAnnotationAndUsesAnnotation() {
		Principal principal = () -> "principal";
		client
			.mutateWith(mockPrincipal(principal))
			.get()
			.exchange()
			.expectStatus().isOk();

		controller.assertPrincipalIsEqualTo(principal);


		client
			.get()
			.exchange()
			.expectStatus().isOk();

		principal = controller.removePrincipal();
		assertPrincipalCreatedFromUserDetails(principal, userBuilder.build());
	}
}
