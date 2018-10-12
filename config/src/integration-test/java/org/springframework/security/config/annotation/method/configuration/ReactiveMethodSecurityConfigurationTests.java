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
package org.springframework.security.config.annotation.method.configuration;

import org.junit.Test;
import org.junit.runner.RunWith;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * @author Eric Deandrea
 * @since 5.1.2
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = ReactiveMethodSecurityConfigurationTests.ReactiveMethodSecurityConfigurationTestsConfig.class)
@ActiveProfiles("ReactiveMethodSecurityConfigurationTests")
public class ReactiveMethodSecurityConfigurationTests {
	@Autowired
	private Methods methods;

	@Test
	public void preAuthorizeMonoTrue() {
		StepVerifier.create(this.methods.preAuthorizeMonoTrue())
				.expectNext(Methods.getSomething())
				.verifyComplete();
	}

	@Test
	public void preAuthorizeMonoFalse() {
		StepVerifier.create(this.methods.preAuthorizeMonoFalse())
				.verifyError(AccessDeniedException.class);
	}

	@Test
	public void postAuthorizeMonoTrue() {
		StepVerifier.create(this.methods.postAuthorizeMonoTrue())
				.expectNext(Methods.getSomething())
				.verifyComplete();
	}

	@Test
	public void postAuthorizeMonoFalse() {
		StepVerifier.create(this.methods.postAuthorizeMonoFalse())
				.verifyError(AccessDeniedException.class);
	}

	@Test
	public void preAuthorizeFluxTrue() {
		StepVerifier.create(this.methods.preAuthorizeFluxTrue())
				.expectNext(Methods.getSomething())
				.expectNext(Methods.getSomethingElse())
				.verifyComplete();
	}

	@Test
	public void preAuthorizeFluxFalse() {
		StepVerifier.create(this.methods.preAuthorizeFluxFalse())
				.verifyError(AccessDeniedException.class);
	}

	@Test
	public void postAuthorizeFluxTrue() {
		StepVerifier.create(this.methods.postAuthorizeFluxTrue())
				.expectNext(Methods.getSomething())
				.expectNext(Methods.getSomethingElse())
				.verifyComplete();
	}

	@Test
	public void postAuthorizeFluxFalse() {
		StepVerifier.create(this.methods.postAuthorizeFluxFalse())
				.verifyError(AccessDeniedException.class);
	}

	@Test
	public void preFilterMonoPasses() {
		StepVerifier.create(this.methods.preFilterMonoPasses(Mono.just(Methods.getSomething())))
				.expectNext(Methods.getSomething())
				.verifyComplete();
	}

	@Test
	public void preFilterMultipleArgsMonoPasses() {
		StepVerifier.create(this.methods.preFilterMultipleArgsMonoPasses(Mono.just(Methods.getSomethingElse()), Mono.just(Methods.getSomething())))
				.expectNext(Methods.getSomething())
				.verifyComplete();
	}

	@Test
	public void preFilterMonoDoesntPass() {
		StepVerifier.create(this.methods.preFilterMonoDoesntPass(Mono.just(Methods.getSomethingElse())))
				.expectNext(Methods.getEmpty())
				.verifyComplete();
	}

	@Test
	public void preFilterMultipleArgsMonoDoesntPass() {
		StepVerifier.create(this.methods.preFilterMultipleArgsMonoDoesntPass(Mono.just(Methods.getSomething()), Mono.just(Methods.getSomethingElse())))
				.expectNext(Methods.getEmpty())
				.verifyComplete();
	}

	@Test
	public void postFilterMonoPasses() {
		StepVerifier.create(this.methods.postFilterMonoPasses(Mono.just(Methods.getSomething())))
				.expectNext(Methods.getSomething())
				.verifyComplete();
	}

	@Test
	public void postFilterMonoDoesntPass() {
		StepVerifier.create(this.methods.postFilterMonoDoesntPass(Mono.just(Methods.getSomethingElse())))
				.verifyComplete();
	}

	@Test
	public void preFilterFluxAllPass() {
		StepVerifier.create(this.methods.preFilterFluxAllPass(Flux.just(Methods.getSomething(), Methods.getSomethingElse())))
				.expectNext(Methods.getSomething())
				.expectNext(Methods.getSomethingElse())
				.verifyComplete();
	}

	@Test
	public void preFilterFluxOnePasses() {
		StepVerifier.create(this.methods.preFilterFluxOnePasses(Flux.just(Methods.getSomething(), Methods.getSomethingElse())))
				.expectNext(Methods.getSomething())
				.verifyComplete();
	}

	@Test
	public void preFilterMultipleArgsFluxAllPass() {
		StepVerifier.create(this.methods.preFilterMultipleArgsFluxAllPass(Mono.just(Methods.getEmpty()), Flux.just(Methods.getSomething(), Methods.getSomethingElse())))
				.expectNext(Methods.getSomething())
				.expectNext(Methods.getSomethingElse())
				.verifyComplete();
	}

	@Test
	public void preFilterMultipleArgsFluxOnePasses() {
		StepVerifier.create(this.methods.preFilterMultipleArgsFluxOnePasses(Mono.just(Methods.getEmpty()), Flux.just(Methods.getSomething(), Methods.getSomethingElse())))
				.expectNext(Methods.getSomething())
				.verifyComplete();
	}

	@Test
	public void postFilterFluxAllPass() {
		StepVerifier.create(this.methods.postFilterFluxAllPass())
				.expectNext(Methods.getSomething())
				.expectNext(Methods.getSomethingElse())
				.verifyComplete();
	}

	@Test
	public void postFilterFluxOnePasses() {
		StepVerifier.create(this.methods.postFilterFluxOnePasses())
				.expectNext(Methods.getSomething())
				.verifyComplete();
	}

	static class Permissions {
		public Mono<Boolean> trueMono() {
			return Mono.just(true);
		}

		public Mono<Boolean> falseMono() {
			return Mono.just(false);
		}

		public Mono<Boolean> allPassFilter(String string) {
			return Mono.just(true);
		}

		public Mono<Boolean> onePassFilter(String string) {
			return Mono.just(Methods.getSomething().equals(string));
		}
	}

	static class Methods {
		public static String getSomething() {
			return "something";
		}

		public static String getSomethingElse() {
			return "something else";
		}

		public static String getEmpty() {
			return "empty";
		}

		@PreAuthorize("@permissions.trueMono()")
		public Mono<String> preAuthorizeMonoTrue() {
			return Mono.just(getSomething());
		}

		@PreAuthorize("@permissions.falseMono()")
		public Mono<String> preAuthorizeMonoFalse() {
			return Mono.just(getSomething());
		}

		@PostAuthorize("@permissions.trueMono()")
		public Mono<String> postAuthorizeMonoTrue() {
			return Mono.just(getSomething());
		}

		@PostAuthorize("@permissions.falseMono()")
		public Mono<String> postAuthorizeMonoFalse() {
			return Mono.just(getSomething());
		}

		@PreAuthorize("@permissions.trueMono()")
		public Flux<String> preAuthorizeFluxTrue() {
			return Flux.just(getSomething(), getSomethingElse());
		}

		@PreAuthorize("@permissions.falseMono()")
		public Flux<String> preAuthorizeFluxFalse() {
			return Flux.just(getSomething(), getSomethingElse());
		}

		@PostAuthorize("@permissions.trueMono()")
		public Flux<String> postAuthorizeFluxTrue() {
			return Flux.just(getSomething(), getSomethingElse());
		}

		@PostAuthorize("@permissions.falseMono()")
		public Flux<String> postAuthorizeFluxFalse() {
			return Flux.just(getSomething(), getSomethingElse());
		}

		@PreFilter("@permissions.allPassFilter(filterObject)")
		public Mono<String> preFilterMonoPasses(Mono<String> mono) {
			return mono.switchIfEmpty(Mono.just(getEmpty()));
		}

		@PreFilter(value = "@permissions.allPassFilter(filterObject)", filterTarget = "mono2")
		public Mono<String> preFilterMultipleArgsMonoPasses(Mono<String> mono1, Mono<String> mono2) {
			return mono2.switchIfEmpty(Mono.just(getEmpty()));
		}

		@PreFilter("@permissions.onePassFilter(filterObject)")
		public Mono<String> preFilterMonoDoesntPass(Mono<String> mono) {
			return mono.switchIfEmpty(Mono.just(getEmpty()));
		}

		@PreFilter(value = "@permissions.onePassFilter(filterObject)", filterTarget = "mono2")
		public Mono<String> preFilterMultipleArgsMonoDoesntPass(Mono<String> mono1, Mono<String> mono2) {
			return mono2.switchIfEmpty(Mono.just(getEmpty()));
		}

		@PostFilter("@permissions.allPassFilter(filterObject)")
		public Mono<String> postFilterMonoPasses(Mono<String> mono) {
			return mono.switchIfEmpty(Mono.just(getEmpty()));
		}

		@PostFilter("@permissions.onePassFilter(filterObject)")
		public Mono<String> postFilterMonoDoesntPass(Mono<String> mono) {
			return mono.switchIfEmpty(Mono.just(getEmpty()));
		}

		@PreFilter("@permissions.allPassFilter(filterObject)")
		public Flux<String> preFilterFluxAllPass(Flux<String> flux) {
			return flux;
		}

		@PreFilter("@permissions.onePassFilter(filterObject)")
		public Flux<String> preFilterFluxOnePasses(Flux<String> flux) {
			return flux;
		}

		@PreFilter(filterTarget = "flux", value = "@permissions.allPassFilter(filterObject)")
		public Flux<String> preFilterMultipleArgsFluxAllPass(Mono<String> mono,  Flux<String> flux) {
			return flux;
		}

		@PreFilter(filterTarget = "flux", value = "@permissions.onePassFilter(filterObject)")
		public Flux<String> preFilterMultipleArgsFluxOnePasses(Mono<String> mono,  Flux<String> flux) {
			return flux;
		}

		@PostFilter("@permissions.allPassFilter(filterObject)")
		public Flux<String> postFilterFluxAllPass() {
			return Flux.just(getSomething(), getSomethingElse());
		}

		@PostFilter("@permissions.onePassFilter(filterObject)")
		public Flux<String> postFilterFluxOnePasses() {
			return Flux.just(getSomething(), getSomethingElse());
		}
	}

	@Configuration
	@Profile("ReactiveMethodSecurityConfigurationTests")
	@EnableWebFluxSecurity
	@EnableReactiveMethodSecurity
	static class ReactiveMethodSecurityConfigurationTestsConfig {
		@Bean
		public Permissions permissions() {
			return new Permissions();
		}

		@Bean
		public Methods methods() {
			return new Methods();
		}

		@Bean
		public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity httpSecurity) {
			return httpSecurity
					.csrf().disable()
					.cors().disable()
					.authorizeExchange()
						.anyExchange().permitAll()
					.and().build();
		}

		@Bean
		public MapReactiveUserDetailsService userDetailsService() {
			UserDetails user = User.withDefaultPasswordEncoder()
					.username("user")
					.password("password")
					.roles("USER")
					.build();

			return new MapReactiveUserDetailsService(user);
		}
	}
}
