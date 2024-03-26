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

package org.springframework.security.config.annotation.method.configuration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link PrePostMethodSecurityConfiguration}.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 */
@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@SecurityTestExecutionListeners
public class AuthorizationProxyConfigurationTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	AuthorizationProxyFactory proxyFactory;

	@WithMockUser
	@Test
	public void proxyWhenNotPreAuthorizedThenDenies() {
		this.spring.register(DefaultsConfig.class).autowire();
		Toaster toaster = (Toaster) this.proxyFactory.proxy(new Toaster());
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(toaster::makeToast)
			.withMessage("Access Denied");
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(toaster::extractBread)
			.withMessage("Access Denied");
	}

	@WithMockUser(roles = "ADMIN")
	@Test
	public void proxyWhenPreAuthorizedThenAllows() {
		this.spring.register(DefaultsConfig.class).autowire();
		Toaster toaster = (Toaster) this.proxyFactory.proxy(new Toaster());
		toaster.makeToast();
		assertThat(toaster.extractBread()).isEqualTo("yummy");
	}

	@Test
	public void proxyReactiveWhenNotPreAuthorizedThenDenies() {
		this.spring.register(ReactiveDefaultsConfig.class).autowire();
		Toaster toaster = (Toaster) this.proxyFactory.proxy(new Toaster());
		Authentication user = TestAuthentication.authenticatedUser();
		StepVerifier
			.create(toaster.reactiveMakeToast().contextWrite(ReactiveSecurityContextHolder.withAuthentication(user)))
			.verifyError(AccessDeniedException.class);
		StepVerifier
			.create(toaster.reactiveExtractBread().contextWrite(ReactiveSecurityContextHolder.withAuthentication(user)))
			.verifyError(AccessDeniedException.class);
	}

	@Test
	public void proxyReactiveWhenPreAuthorizedThenAllows() {
		this.spring.register(ReactiveDefaultsConfig.class).autowire();
		Toaster toaster = (Toaster) this.proxyFactory.proxy(new Toaster());
		Authentication admin = TestAuthentication.authenticatedAdmin();
		StepVerifier
			.create(toaster.reactiveMakeToast().contextWrite(ReactiveSecurityContextHolder.withAuthentication(admin)))
			.expectNext()
			.verifyComplete();
	}

	@EnableMethodSecurity
	@Configuration
	static class DefaultsConfig {

	}

	@EnableReactiveMethodSecurity
	@Configuration
	static class ReactiveDefaultsConfig {

	}

	static class Toaster {

		@PreAuthorize("hasRole('ADMIN')")
		void makeToast() {

		}

		@PostAuthorize("hasRole('ADMIN')")
		String extractBread() {
			return "yummy";
		}

		@PreAuthorize("hasRole('ADMIN')")
		Mono<Void> reactiveMakeToast() {
			return Mono.empty();
		}

		@PostAuthorize("hasRole('ADMIN')")
		Mono<String> reactiveExtractBread() {
			return Mono.just("yummy");
		}

	}

}
