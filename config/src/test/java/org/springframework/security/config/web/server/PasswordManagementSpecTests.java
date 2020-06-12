/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.config.web.server;

import org.apache.http.HttpHeaders;
import org.junit.Test;

import org.springframework.security.config.annotation.web.reactive.ServerHttpSecurityConfigurationBuilder;
import org.springframework.security.config.web.server.ServerHttpSecurity.PasswordManagementSpec;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link PasswordManagementSpec}.
 *
 * @author Evgeniy Cheban
 */
public class PasswordManagementSpecTests {

	ServerHttpSecurity http = ServerHttpSecurityConfigurationBuilder.httpWithDefaultAuthentication();

	@Test
	public void whenChangePasswordPageNotSetThenDefaultChangePasswordPageUsed() {
		this.http.passwordManagement();

		WebTestClient client = buildClient();
		client.get().uri("/.well-known/change-password").exchange().expectStatus().isFound().expectHeader()
				.valueEquals(HttpHeaders.LOCATION, "/change-password");
	}

	@Test
	public void whenChangePasswordPageSetThenSpecifiedChangePasswordPageUsed() {
		this.http.passwordManagement(
				(passwordManagement) -> passwordManagement.changePasswordPage("/custom-change-password-page"));

		WebTestClient client = buildClient();
		client.get().uri("/.well-known/change-password").exchange().expectStatus().isFound().expectHeader()
				.valueEquals(HttpHeaders.LOCATION, "/custom-change-password-page");
	}

	private WebTestClient buildClient() {
		return WebTestClientBuilder.bindToWebFilters(this.http.build()).build();
	}

	@Test
	public void whenSettingNullChangePasswordPage() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.http.passwordManagement().changePasswordPage(null))
				.withMessage("changePasswordPage cannot be empty");
	}

	@Test
	public void whenSettingEmptyChangePasswordPage() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.http.passwordManagement().changePasswordPage(""))
				.withMessage("changePasswordPage cannot be empty");
	}

	@Test
	public void whenSettingBlankChangePasswordPage() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.http.passwordManagement().changePasswordPage(" "))
				.withMessage("changePasswordPage cannot be empty");
	}

}
