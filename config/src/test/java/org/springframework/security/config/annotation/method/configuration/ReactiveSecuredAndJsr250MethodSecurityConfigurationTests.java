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

package org.springframework.security.config.annotation.method.configuration;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.ObservationTextPublisher;
import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThatException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link EnableReactiveMethodSecurity#jsr250Enabled()} and
 * {@link EnableReactiveMethodSecurity#securedEnabled()}.
 *
 * @author Rohit Behera
 */
@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@SecurityTestExecutionListeners
public class ReactiveSecuredAndJsr250MethodSecurityConfigurationTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	@WithMockUser(roles = "ADMIN")
	void rolesAllowedWhenJsr250EnabledAndRoleAdminThenGranted() {
		this.spring.register(Jsr250Config.class).autowire();
		Jsr250Service service = this.spring.getContext().getBean(Jsr250Service.class);
		StepVerifier.create(service.rolesAllowedAdmin()).expectNext("admin").verifyComplete();
	}

	@Test
	@WithMockUser
	void rolesAllowedWhenJsr250EnabledAndRoleUserThenDenied() {
		this.spring.register(Jsr250Config.class).autowire();
		Jsr250Service service = this.spring.getContext().getBean(Jsr250Service.class);
		StepVerifier.create(service.rolesAllowedAdmin()).expectError(AccessDeniedException.class).verify();
	}

	@Test
	void rolesAllowedWhenJsr250EnabledAndAnonymousThenDenied() {
		this.spring.register(Jsr250Config.class).autowire();
		Jsr250Service service = this.spring.getContext().getBean(Jsr250Service.class);
		StepVerifier.create(service.rolesAllowedAdmin()).expectError(AccessDeniedException.class).verify();
	}

	@Test
	@WithMockUser
	void rolesAllowedFluxWhenJsr250EnabledAndRoleUserThenDenied() {
		this.spring.register(Jsr250Config.class).autowire();
		Jsr250Service service = this.spring.getContext().getBean(Jsr250Service.class);
		StepVerifier.create(service.rolesAllowedAdminFlux()).expectError(AccessDeniedException.class).verify();
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void rolesAllowedFluxWhenJsr250EnabledAndRoleAdminThenGranted() {
		this.spring.register(Jsr250Config.class).autowire();
		Jsr250Service service = this.spring.getContext().getBean(Jsr250Service.class);
		StepVerifier.create(service.rolesAllowedAdminFlux()).expectNext("a", "b").verifyComplete();
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void denyAllWhenJsr250EnabledThenDenied() {
		this.spring.register(Jsr250Config.class).autowire();
		Jsr250Service service = this.spring.getContext().getBean(Jsr250Service.class);
		StepVerifier.create(service.denyAll()).expectError(AccessDeniedException.class).verify();
	}

	@Test
	void permitAllWhenJsr250EnabledAndAnonymousThenGranted() {
		this.spring.register(Jsr250Config.class).autowire();
		Jsr250Service service = this.spring.getContext().getBean(Jsr250Service.class);
		StepVerifier.create(service.permitAll()).expectNext("permitAll").verifyComplete();
	}

	@Test
	@WithMockUser
	void classLevelRolesAllowedWhenJsr250EnabledThenAppliesToMethod() {
		this.spring.register(Jsr250Config.class).autowire();
		ClassLevelJsr250Service service = this.spring.getContext().getBean(ClassLevelJsr250Service.class);
		StepVerifier.create(service.inheritsUser()).expectNext("user").verifyComplete();
		StepVerifier.create(service.overridesAdmin()).expectError(AccessDeniedException.class).verify();
	}

	@Test
	@WithMockUser
	void rolesAllowedWhenJsr250NotEnabledThenNotEnforced() {
		this.spring.register(DefaultConfig.class).autowire();
		Jsr250Service service = this.spring.getContext().getBean(Jsr250Service.class);
		StepVerifier.create(service.rolesAllowedAdmin()).expectNext("admin").verifyComplete();
		StepVerifier.create(service.denyAll()).expectNext("denyAll").verifyComplete();
	}

	@Test
	@WithMockUser(authorities = "CUSTOM_ADMIN")
	void rolesAllowedWhenGrantedAuthorityDefaultsThenUsesRolePrefix() {
		this.spring.register(Jsr250Config.class, CustomRolePrefixConfig.class).autowire();
		Jsr250Service service = this.spring.getContext().getBean(Jsr250Service.class);
		StepVerifier.create(service.rolesAllowedAdmin()).expectNext("admin").verifyComplete();
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void rolesAllowedWhenRoleHierarchyThenUsesHierarchy() {
		this.spring.register(Jsr250Config.class, RoleHierarchyConfig.class).autowire();
		Jsr250Service service = this.spring.getContext().getBean(Jsr250Service.class);
		StepVerifier.create(service.rolesAllowedUser()).expectNext("user").verifyComplete();
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void securedWhenSecuredEnabledAndRoleAdminThenGranted() {
		this.spring.register(SecuredConfig.class).autowire();
		SecuredService service = this.spring.getContext().getBean(SecuredService.class);
		StepVerifier.create(service.securedAdmin()).expectNext("admin").verifyComplete();
	}

	@Test
	@WithMockUser
	void securedWhenSecuredEnabledAndRoleUserThenDenied() {
		this.spring.register(SecuredConfig.class).autowire();
		SecuredService service = this.spring.getContext().getBean(SecuredService.class);
		StepVerifier.create(service.securedAdmin()).expectError(AccessDeniedException.class).verify();
		StepVerifier.create(service.securedAdminFlux()).expectError(AccessDeniedException.class).verify();
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void securedWhenRoleHierarchyThenUsesHierarchy() {
		this.spring.register(SecuredConfig.class, RoleHierarchyConfig.class).autowire();
		SecuredService service = this.spring.getContext().getBean(SecuredService.class);
		StepVerifier.create(service.securedUser()).expectNext("user").verifyComplete();
	}

	@Test
	@WithMockUser
	void securedWhenSecuredNotEnabledThenNotEnforced() {
		this.spring.register(Jsr250Config.class).autowire();
		SecuredService service = this.spring.getContext().getBean(SecuredService.class);
		StepVerifier.create(service.securedAdmin()).expectNext("admin").verifyComplete();
	}

	@Test
	@WithMockUser
	void rolesAllowedWhenOnlySecuredEnabledThenNotEnforced() {
		this.spring.register(SecuredConfig.class).autowire();
		Jsr250Service service = this.spring.getContext().getBean(Jsr250Service.class);
		StepVerifier.create(service.rolesAllowedAdmin()).expectNext("admin").verifyComplete();
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void interfaceAnnotationsWhenBothEnabledAndRoleAdminThenGranted() {
		this.spring.register(BothConfig.class).autowire();
		AnnotatedInterfaceService service = this.spring.getContext().getBean(AnnotatedInterfaceService.class);
		StepVerifier.create(service.rolesAllowedAdmin()).expectNext("admin").verifyComplete();
		StepVerifier.create(service.securedAdmin()).expectNext("admin").verifyComplete();
	}

	@Test
	@WithMockUser
	void interfaceAnnotationsWhenBothEnabledAndRoleUserThenDenied() {
		this.spring.register(BothConfig.class).autowire();
		AnnotatedInterfaceService service = this.spring.getContext().getBean(AnnotatedInterfaceService.class);
		StepVerifier.create(service.rolesAllowedAdmin()).expectError(AccessDeniedException.class).verify();
		StepVerifier.create(service.securedAdmin()).expectError(AccessDeniedException.class).verify();
	}

	@Test
	@WithMockUser(roles = { "USER", "ADMIN" })
	void preAuthorizeAndRolesAllowedWhenBothSatisfiedThenGranted() {
		this.spring.register(Jsr250Config.class).autowire();
		Jsr250Service service = this.spring.getContext().getBean(Jsr250Service.class);
		StepVerifier.create(service.preAuthorizeUserAndRolesAllowedAdmin()).expectNext("both").verifyComplete();
	}

	@Test
	@WithMockUser
	void preAuthorizeAndRolesAllowedWhenOnlyPreAuthorizeSatisfiedThenDenied() {
		this.spring.register(Jsr250Config.class).autowire();
		Jsr250Service service = this.spring.getContext().getBean(Jsr250Service.class);
		StepVerifier.create(service.preAuthorizeUserAndRolesAllowedAdmin())
			.expectError(AccessDeniedException.class)
			.verify();
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void preAuthorizeAndRolesAllowedWhenOnlyRolesAllowedSatisfiedThenDenied() {
		this.spring.register(Jsr250Config.class).autowire();
		Jsr250Service service = this.spring.getContext().getBean(Jsr250Service.class);
		StepVerifier.create(service.preAuthorizeUserAndRolesAllowedAdmin())
			.expectError(AccessDeniedException.class)
			.verify();
	}

	@Test
	@WithMockUser
	void rolesAllowedWhenObservationRegistryThenObserved() {
		this.spring.register(Jsr250Config.class, ObservationConfig.class).autowire();
		Jsr250Service service = this.spring.getContext().getBean(Jsr250Service.class);
		ObservationHandler<?> handler = this.spring.getContext().getBean(ObservationHandler.class);
		StepVerifier.create(service.rolesAllowedUser()).expectNext("user").verifyComplete();
		verify(handler).onStart(any());
		verify(handler).onStop(any());
		StepVerifier.create(service.rolesAllowedAdmin()).expectError(AccessDeniedException.class).verify();
		verify(handler).onError(any());
	}

	@Test
	@WithMockUser
	void securedWhenObservationRegistryThenObserved() {
		this.spring.register(SecuredConfig.class, ObservationConfig.class).autowire();
		SecuredService service = this.spring.getContext().getBean(SecuredService.class);
		ObservationHandler<?> handler = this.spring.getContext().getBean(ObservationHandler.class);
		StepVerifier.create(service.securedUser()).expectNext("user").verifyComplete();
		verify(handler).onStart(any());
		verify(handler).onStop(any());
		StepVerifier.create(service.securedAdmin()).expectError(AccessDeniedException.class).verify();
		verify(handler).onError(any());
	}

	@Test
	void configureWhenJsr250EnabledWithoutAuthorizationManagerThenFails() {
		assertThatException().isThrownBy(() -> this.spring.register(LegacyJsr250Config.class).autowire())
			.havingRootCause()
			.isInstanceOf(IllegalStateException.class)
			.withMessageContaining("require useAuthorizationManager = true");
	}

	@Test
	void configureWhenSecuredEnabledWithoutAuthorizationManagerThenFails() {
		assertThatException().isThrownBy(() -> this.spring.register(LegacySecuredConfig.class).autowire())
			.havingRootCause()
			.isInstanceOf(IllegalStateException.class)
			.withMessageContaining("require useAuthorizationManager = true");
	}

	public static class Jsr250Service {

		@RolesAllowed("ADMIN")
		public Mono<String> rolesAllowedAdmin() {
			return Mono.just("admin");
		}

		@RolesAllowed("ADMIN")
		public Flux<String> rolesAllowedAdminFlux() {
			return Flux.just("a", "b");
		}

		@RolesAllowed("USER")
		public Mono<String> rolesAllowedUser() {
			return Mono.just("user");
		}

		@DenyAll
		public Mono<String> denyAll() {
			return Mono.just("denyAll");
		}

		@PermitAll
		public Mono<String> permitAll() {
			return Mono.just("permitAll");
		}

		@PreAuthorize("hasRole('USER')")
		@RolesAllowed("ADMIN")
		public Mono<String> preAuthorizeUserAndRolesAllowedAdmin() {
			return Mono.just("both");
		}

	}

	public interface AnnotatedInterfaceService {

		@RolesAllowed("ADMIN")
		Mono<String> rolesAllowedAdmin();

		@Secured("ROLE_ADMIN")
		Mono<String> securedAdmin();

	}

	public static class AnnotatedInterfaceServiceImpl implements AnnotatedInterfaceService {

		@Override
		public Mono<String> rolesAllowedAdmin() {
			return Mono.just("admin");
		}

		@Override
		public Mono<String> securedAdmin() {
			return Mono.just("admin");
		}

	}

	@RolesAllowed("USER")
	public static class ClassLevelJsr250Service {

		public Mono<String> inheritsUser() {
			return Mono.just("user");
		}

		@RolesAllowed("ADMIN")
		public Mono<String> overridesAdmin() {
			return Mono.just("admin");
		}

	}

	public static class SecuredService {

		@Secured("ROLE_ADMIN")
		public Mono<String> securedAdmin() {
			return Mono.just("admin");
		}

		@Secured("ROLE_ADMIN")
		public Flux<String> securedAdminFlux() {
			return Flux.just("a", "b");
		}

		@Secured("ROLE_USER")
		public Mono<String> securedUser() {
			return Mono.just("user");
		}

	}

	@Configuration
	static class ServicesConfig {

		@Bean
		Jsr250Service jsr250Service() {
			return new Jsr250Service();
		}

		@Bean
		ClassLevelJsr250Service classLevelJsr250Service() {
			return new ClassLevelJsr250Service();
		}

		@Bean
		SecuredService securedService() {
			return new SecuredService();
		}

		@Bean
		AnnotatedInterfaceService annotatedInterfaceService() {
			return new AnnotatedInterfaceServiceImpl();
		}

	}

	@Configuration
	@EnableReactiveMethodSecurity(jsr250Enabled = true)
	static class Jsr250Config extends ServicesConfig {

	}

	@Configuration
	@EnableReactiveMethodSecurity(securedEnabled = true)
	static class SecuredConfig extends ServicesConfig {

	}

	@Configuration
	@EnableReactiveMethodSecurity(securedEnabled = true, jsr250Enabled = true)
	static class BothConfig extends ServicesConfig {

	}

	@Configuration
	@EnableReactiveMethodSecurity
	static class DefaultConfig extends ServicesConfig {

	}

	@Configuration
	@EnableReactiveMethodSecurity(useAuthorizationManager = false, jsr250Enabled = true)
	static class LegacyJsr250Config extends ServicesConfig {

	}

	@Configuration
	@EnableReactiveMethodSecurity(useAuthorizationManager = false, securedEnabled = true)
	static class LegacySecuredConfig extends ServicesConfig {

	}

	@Configuration
	static class CustomRolePrefixConfig {

		@Bean
		static GrantedAuthorityDefaults grantedAuthorityDefaults() {
			return new GrantedAuthorityDefaults("CUSTOM_");
		}

	}

	@Configuration
	static class ObservationConfig {

		private final ObservationHandler<Observation.Context> handler = spy(new ObservationTextPublisher());

		@Bean
		ObservationRegistry observationRegistry() {
			ObservationRegistry registry = ObservationRegistry.create();
			registry.observationConfig().observationHandler(this.handler);
			return registry;
		}

		@Bean
		ObservationHandler<Observation.Context> observationHandler() {
			return this.handler;
		}

	}

	@Configuration
	static class RoleHierarchyConfig {

		@Bean
		static RoleHierarchy roleHierarchy() {
			return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_USER");
		}

	}

}
