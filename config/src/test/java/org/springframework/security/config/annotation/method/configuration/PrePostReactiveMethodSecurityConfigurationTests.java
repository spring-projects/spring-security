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

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.annotation.security.DenyAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.aop.config.AopConfigUtils;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.security.authorization.method.PrePostTemplateDefaults;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.stereotype.Component;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@SecurityTestExecutionListeners
public class PrePostReactiveMethodSecurityConfigurationTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	@WithMockUser
	void getCardNumberWhenPostAuthorizeAndNotAdminThenReturnMasked() {
		this.spring
			.register(MethodSecurityServiceEnabledConfig.class,
					ReactiveMethodSecurityService.CardNumberMaskingPostProcessor.class)
			.autowire();
		ReactiveMethodSecurityService service = this.spring.getContext().getBean(ReactiveMethodSecurityService.class);
		StepVerifier.create(service.postAuthorizeGetCardNumberIfAdmin("4444-3333-2222-1111"))
			.expectNext("****-****-****-1111")
			.verifyComplete();
	}

	@Test
	@WithMockUser
	void getCardNumberWhenPreAuthorizeAndNotAdminThenReturnMasked() {
		this.spring
			.register(MethodSecurityServiceEnabledConfig.class, ReactiveMethodSecurityService.StarMaskingHandler.class)
			.autowire();
		ReactiveMethodSecurityService service = this.spring.getContext().getBean(ReactiveMethodSecurityService.class);
		StepVerifier.create(service.preAuthorizeGetCardNumberIfAdmin("4444-3333-2222-1111"))
			.expectNext("***")
			.verifyComplete();
	}

	@Test
	@WithMockUser
	void getCardNumberWhenPreAuthorizeAndNotAdminAndChildHandlerThenResolveCorrectHandlerAndReturnMasked() {
		this.spring
			.register(MethodSecurityServiceEnabledConfig.class, ReactiveMethodSecurityService.StarMaskingHandler.class,
					ReactiveMethodSecurityService.StartMaskingHandlerChild.class)
			.autowire();
		ReactiveMethodSecurityService service = this.spring.getContext().getBean(ReactiveMethodSecurityService.class);
		StepVerifier.create(service.preAuthorizeWithHandlerChildGetCardNumberIfAdmin("4444-3333-2222-1111"))
			.expectNext("***-child")
			.verifyComplete();
	}

	@Test
	@WithMockUser
	void preAuthorizeWhenDeniedAndHandlerWithCustomAnnotationThenHandlerCanUseMaskFromOtherAnnotation() {
		this.spring
			.register(MethodSecurityServiceEnabledConfig.class,
					ReactiveMethodSecurityService.MaskAnnotationHandler.class)
			.autowire();
		ReactiveMethodSecurityService service = this.spring.getContext().getBean(ReactiveMethodSecurityService.class);
		StepVerifier.create(service.preAuthorizeDeniedMethodWithMaskAnnotation())
			.expectNext("methodmask")
			.verifyComplete();
	}

	@Test
	@WithMockUser
	void preAuthorizeWhenDeniedAndHandlerWithCustomAnnotationInClassThenHandlerCanUseMaskFromOtherAnnotation() {
		this.spring
			.register(MethodSecurityServiceEnabledConfig.class,
					ReactiveMethodSecurityService.MaskAnnotationHandler.class)
			.autowire();
		ReactiveMethodSecurityService service = this.spring.getContext().getBean(ReactiveMethodSecurityService.class);
		StepVerifier.create(service.preAuthorizeDeniedMethodWithNoMaskAnnotation())
			.expectNext("classmask")
			.verifyComplete();
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void postAuthorizeWhenHandlerAndAccessDeniedNotThrownFromPostAuthorizeThenNotHandled() {
		this.spring
			.register(MethodSecurityServiceEnabledConfig.class,
					ReactiveMethodSecurityService.PostMaskingPostProcessor.class)
			.autowire();
		ReactiveMethodSecurityService service = this.spring.getContext().getBean(ReactiveMethodSecurityService.class);
		StepVerifier.create(service.postAuthorizeThrowAccessDeniedManually()).expectNext("***").verifyComplete();
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void preAuthorizeWhenHandlerAndAccessDeniedNotThrownFromPreAuthorizeThenHandled() {
		this.spring
			.register(MethodSecurityServiceEnabledConfig.class, ReactiveMethodSecurityService.StarMaskingHandler.class)
			.autowire();
		ReactiveMethodSecurityService service = this.spring.getContext().getBean(ReactiveMethodSecurityService.class);
		StepVerifier.create(service.preAuthorizeThrowAccessDeniedManually()).expectNext("***").verifyComplete();
	}

	@Test
	@WithMockUser
	void postAuthorizeWhenNullDeniedMetaAnnotationThanWorks() {
		this.spring
			.register(MethodSecurityServiceEnabledConfig.class, ReactiveMethodSecurityService.NullPostProcessor.class)
			.autowire();
		ReactiveMethodSecurityService service = this.spring.getContext().getBean(ReactiveMethodSecurityService.class);
		StepVerifier.create(service.postAuthorizeDeniedWithNullDenied()).verifyComplete();
	}

	@Test
	@WithMockUser
	void postAuthorizeWhenDeniedAndHandlerWithCustomAnnotationThenHandlerCanUseMaskFromOtherAnnotation() {
		this.spring
			.register(MethodSecurityServiceEnabledConfig.class,
					ReactiveMethodSecurityService.MaskAnnotationPostProcessor.class)
			.autowire();
		ReactiveMethodSecurityService service = this.spring.getContext().getBean(ReactiveMethodSecurityService.class);
		StepVerifier.create(service.postAuthorizeDeniedMethodWithMaskAnnotation())
			.expectNext("methodmask")
			.verifyComplete();
	}

	@Test
	@WithMockUser
	void postAuthorizeWhenDeniedAndHandlerWithCustomAnnotationInClassThenHandlerCanUseMaskFromOtherAnnotation() {
		this.spring
			.register(MethodSecurityServiceEnabledConfig.class,
					ReactiveMethodSecurityService.MaskAnnotationPostProcessor.class)
			.autowire();
		ReactiveMethodSecurityService service = this.spring.getContext().getBean(ReactiveMethodSecurityService.class);
		StepVerifier.create(service.postAuthorizeDeniedMethodWithNoMaskAnnotation())
			.expectNext("classmask")
			.verifyComplete();
	}

	@Test
	@WithMockUser
	void postAuthorizeWhenDeniedAndHandlerWithCustomAnnotationUsingBeanThenHandlerCanUseMaskFromOtherAnnotation() {
		this.spring
			.register(MethodSecurityServiceEnabledConfig.class,
					ReactiveMethodSecurityService.MaskAnnotationPostProcessor.class, MyMasker.class)
			.autowire();
		ReactiveMethodSecurityService service = this.spring.getContext().getBean(ReactiveMethodSecurityService.class);
		StepVerifier.create(service.postAuthorizeWithMaskAnnotationUsingBean())
			.expectNext("ok-masked")
			.verifyComplete();
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void postAuthorizeWhenAllowedAndHandlerWithCustomAnnotationUsingBeanThenInvokeMethodNormally() {
		this.spring
			.register(MethodSecurityServiceEnabledConfig.class,
					ReactiveMethodSecurityService.MaskAnnotationPostProcessor.class, MyMasker.class)
			.autowire();
		ReactiveMethodSecurityService service = this.spring.getContext().getBean(ReactiveMethodSecurityService.class);
		StepVerifier.create(service.postAuthorizeWithMaskAnnotationUsingBean()).expectNext("ok").verifyComplete();
	}

	@Test
	@WithMockUser
	void preAuthorizeWhenDeniedAndHandlerWithCustomAnnotationUsingBeanThenHandlerCanUseMaskFromOtherAnnotation() {
		this.spring
			.register(MethodSecurityServiceEnabledConfig.class,
					ReactiveMethodSecurityService.MaskAnnotationHandler.class, MyMasker.class)
			.autowire();
		ReactiveMethodSecurityService service = this.spring.getContext().getBean(ReactiveMethodSecurityService.class);
		StepVerifier.create(service.preAuthorizeWithMaskAnnotationUsingBean()).expectNext("mask").verifyComplete();
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void preAuthorizeWhenAllowedAndHandlerWithCustomAnnotationUsingBeanThenInvokeMethodNormally() {
		this.spring
			.register(MethodSecurityServiceEnabledConfig.class,
					ReactiveMethodSecurityService.MaskAnnotationHandler.class, MyMasker.class)
			.autowire();
		ReactiveMethodSecurityService service = this.spring.getContext().getBean(ReactiveMethodSecurityService.class);
		StepVerifier.create(service.preAuthorizeWithMaskAnnotationUsingBean()).expectNext("ok").verifyComplete();
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	public void preAuthorizeWhenCustomMethodSecurityExpressionHandlerThenUses() {
		this.spring.register(MethodSecurityServiceEnabledConfig.class, PermissionEvaluatorConfig.class).autowire();
		ReactiveMethodSecurityService service = this.spring.getContext().getBean(ReactiveMethodSecurityService.class);
		PermissionEvaluator permissionEvaluator = this.spring.getContext().getBean(PermissionEvaluator.class);
		given(permissionEvaluator.hasPermission(any(), eq("grant"), any())).willReturn(true);
		given(permissionEvaluator.hasPermission(any(), eq("deny"), any())).willReturn(false);
		StepVerifier.create(service.preAuthorizeHasPermission("grant")).expectNext("ok").verifyComplete();
		StepVerifier.create(service.preAuthorizeHasPermission("deny"))
			.expectError(AuthorizationDeniedException.class)
			.verify();
		verify(permissionEvaluator, times(2)).hasPermission(any(), any(), any());
	}

	@ParameterizedTest
	@ValueSource(classes = { LegacyMetaAnnotationPlaceholderConfig.class, MetaAnnotationPlaceholderConfig.class })
	@WithMockUser
	public void methodeWhenParameterizedPreAuthorizeMetaAnnotationThenPasses(Class<?> config) {
		this.spring.register(config).autowire();
		MetaAnnotationService service = this.spring.getContext().getBean(MetaAnnotationService.class);
		assertThat(service.hasRole("USER").block()).isTrue();
	}

	@ParameterizedTest
	@ValueSource(classes = { LegacyMetaAnnotationPlaceholderConfig.class, MetaAnnotationPlaceholderConfig.class })
	@WithMockUser
	public void methodRoleWhenPreAuthorizeMetaAnnotationHardcodedParameterThenPasses(Class<?> config) {
		this.spring.register(config).autowire();
		MetaAnnotationService service = this.spring.getContext().getBean(MetaAnnotationService.class);
		assertThat(service.hasUserRole().block()).isTrue();
	}

	@ParameterizedTest
	@ValueSource(classes = { LegacyMetaAnnotationPlaceholderConfig.class, MetaAnnotationPlaceholderConfig.class })
	public void methodWhenParameterizedAnnotationThenFails(Class<?> config) {
		this.spring.register(config).autowire();
		MetaAnnotationService service = this.spring.getContext().getBean(MetaAnnotationService.class);
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> service.placeholdersOnlyResolvedByMetaAnnotations().block());
	}

	@ParameterizedTest
	@ValueSource(classes = { LegacyMetaAnnotationPlaceholderConfig.class, MetaAnnotationPlaceholderConfig.class })
	@WithMockUser(authorities = "SCOPE_message:read")
	public void methodWhenMultiplePlaceholdersHasAuthorityThenPasses(Class<?> config) {
		this.spring.register(config).autowire();
		MetaAnnotationService service = this.spring.getContext().getBean(MetaAnnotationService.class);
		assertThat(service.readMessage().block()).isEqualTo("message");
	}

	@ParameterizedTest
	@ValueSource(classes = { LegacyMetaAnnotationPlaceholderConfig.class, MetaAnnotationPlaceholderConfig.class })
	@WithMockUser(roles = "ADMIN")
	public void methodWhenMultiplePlaceholdersHasRoleThenPasses(Class<?> config) {
		this.spring.register(config).autowire();
		MetaAnnotationService service = this.spring.getContext().getBean(MetaAnnotationService.class);
		assertThat(service.readMessage().block()).isEqualTo("message");
	}

	@ParameterizedTest
	@ValueSource(classes = { LegacyMetaAnnotationPlaceholderConfig.class, MetaAnnotationPlaceholderConfig.class })
	@WithMockUser
	public void methodWhenPostAuthorizeMetaAnnotationThenAuthorizes(Class<?> config) {
		this.spring.register(config).autowire();
		MetaAnnotationService service = this.spring.getContext().getBean(MetaAnnotationService.class);
		service.startsWithDave("daveMatthews");
		assertThatExceptionOfType(AccessDeniedException.class)
			.isThrownBy(() -> service.startsWithDave("jenniferHarper").block());
	}

	@ParameterizedTest
	@ValueSource(classes = { LegacyMetaAnnotationPlaceholderConfig.class, MetaAnnotationPlaceholderConfig.class })
	@WithMockUser
	public void methodWhenPreFilterMetaAnnotationThenFilters(Class<?> config) {
		this.spring.register(config).autowire();
		MetaAnnotationService service = this.spring.getContext().getBean(MetaAnnotationService.class);
		assertThat(service.parametersContainDave(Flux.just("dave", "carla", "vanessa", "paul")).collectList().block())
			.containsExactly("dave");
	}

	@ParameterizedTest
	@ValueSource(classes = { LegacyMetaAnnotationPlaceholderConfig.class, MetaAnnotationPlaceholderConfig.class })
	@WithMockUser
	public void methodWhenPostFilterMetaAnnotationThenFilters(Class<?> config) {
		this.spring.register(config).autowire();
		MetaAnnotationService service = this.spring.getContext().getBean(MetaAnnotationService.class);
		assertThat(service.resultsContainDave(Flux.just("dave", "carla", "vanessa", "paul")).collectList().block())
			.containsExactly("dave");
	}

	@Test
	@WithMockUser(authorities = "airplane:read")
	public void findByIdWhenAuthorizedResultThenAuthorizes() {
		this.spring.register(AuthorizeResultConfig.class).autowire();
		FlightRepository flights = this.spring.getContext().getBean(FlightRepository.class);
		Flight flight = flights.findById("1").block();
		assertThatNoException().isThrownBy(flight::getAltitude);
		assertThatNoException().isThrownBy(flight::getSeats);
	}

	@Test
	@WithMockUser(authorities = "seating:read")
	public void findByIdWhenUnauthorizedResultThenDenies() {
		this.spring.register(AuthorizeResultConfig.class).autowire();
		FlightRepository flights = this.spring.getContext().getBean(FlightRepository.class);
		Flight flight = flights.findById("1").block();
		assertThatNoException().isThrownBy(flight::getSeats);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> flight.getAltitude().block());
	}

	@Test
	@WithMockUser(authorities = "seating:read")
	public void findAllWhenUnauthorizedResultThenDenies() {
		this.spring.register(AuthorizeResultConfig.class).autowire();
		FlightRepository flights = this.spring.getContext().getBean(FlightRepository.class);
		flights.findAll().collectList().block().forEach((flight) -> {
			assertThatNoException().isThrownBy(flight::getSeats);
			assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> flight.getAltitude().block());
		});
	}

	@Test
	public void removeWhenAuthorizedResultThenRemoves() {
		this.spring.register(AuthorizeResultConfig.class).autowire();
		FlightRepository flights = this.spring.getContext().getBean(FlightRepository.class);
		flights.remove("1");
	}

	@Test
	@WithMockUser(authorities = "airplane:read")
	public void findAllWhenPostFilterThenFilters() {
		this.spring.register(AuthorizeResultConfig.class).autowire();
		FlightRepository flights = this.spring.getContext().getBean(FlightRepository.class);
		flights.findAll()
			.collectList()
			.block()
			.forEach((flight) -> assertThat(flight.getPassengers().collectList().block())
				.extracting((p) -> p.getName().block())
				.doesNotContain("Kevin Mitnick"));
	}

	@Test
	@WithMockUser(authorities = "airplane:read")
	public void findAllWhenPreFilterThenFilters() {
		this.spring.register(AuthorizeResultConfig.class).autowire();
		FlightRepository flights = this.spring.getContext().getBean(FlightRepository.class);
		flights.findAll().collectList().block().forEach((flight) -> {
			flight.board(Flux.just("John")).block();
			assertThat(flight.getPassengers().collectList().block()).extracting((p) -> p.getName().block())
				.doesNotContain("John");
			flight.board(Flux.just("John Doe")).block();
			assertThat(flight.getPassengers().collectList().block()).extracting((p) -> p.getName().block())
				.contains("John Doe");
		});
	}

	@Test
	@WithMockUser(authorities = "seating:read")
	public void findAllWhenNestedPreAuthorizeThenAuthorizes() {
		this.spring.register(AuthorizeResultConfig.class).autowire();
		FlightRepository flights = this.spring.getContext().getBean(FlightRepository.class);
		flights.findAll().collectList().block().forEach((flight) -> {
			List<Passenger> passengers = flight.getPassengers().collectList().block();
			passengers.forEach((passenger) -> assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> passenger.getName().block()));
		});
	}

	// gh-15352
	@Test
	void annotationsInChildClassesDoNotAffectSuperclasses() {
		this.spring.register(AbstractClassConfig.class).autowire();
		this.spring.getContext().getBean(ClassInheritingAbstractClassWithNoAnnotations.class).method();
	}

	// gh-15592
	@Test
	void autowireWhenDefaultsThenCreatesExactlyOneAdvisorPerAnnotation() {
		this.spring.register(MethodSecurityServiceEnabledConfig.class).autowire();
		AuthorizationAdvisorProxyFactory proxyFactory = this.spring.getContext()
			.getBean(AuthorizationAdvisorProxyFactory.class);
		assertThat(proxyFactory).hasSize(5);
		assertThat(this.spring.getContext().getBeanNamesForType(AuthorizationAdvisor.class)).hasSize(5)
			.containsExactlyInAnyOrder("preFilterAuthorizationMethodInterceptor",
					"preAuthorizeAuthorizationMethodInterceptor", "postAuthorizeAuthorizationMethodInterceptor",
					"postFilterAuthorizationMethodInterceptor", "authorizeReturnObjectMethodInterceptor");
	}

	// gh-15592
	@Test
	void autowireWhenAspectJAutoProxyAndFactoryBeanThenExactlyOneAdvisorPerAnnotation() {
		this.spring.register(AspectJAwareAutoProxyAndFactoryBeansConfig.class).autowire();
		AuthorizationAdvisorProxyFactory proxyFactory = this.spring.getContext()
			.getBean(AuthorizationAdvisorProxyFactory.class);
		assertThat(proxyFactory).hasSize(5);
		assertThat(this.spring.getContext().getBeanNamesForType(AuthorizationAdvisor.class)).hasSize(5)
			.containsExactlyInAnyOrder("preFilterAuthorizationMethodInterceptor",
					"preAuthorizeAuthorizationMethodInterceptor", "postAuthorizeAuthorizationMethodInterceptor",
					"postFilterAuthorizationMethodInterceptor", "authorizeReturnObjectMethodInterceptor");
	}

	// gh-15651
	@Test
	@WithMockUser(roles = "ADMIN")
	public void adviseWhenPrePostEnabledThenEachInterceptorRunsExactlyOnce() {
		this.spring
			.register(MethodSecurityServiceEnabledConfig.class, CustomMethodSecurityExpressionHandlerConfig.class)
			.autowire();
		MethodSecurityExpressionHandler expressionHandler = this.spring.getContext()
			.getBean(MethodSecurityExpressionHandler.class);
		ReactiveMethodSecurityService service = this.spring.getContext().getBean(ReactiveMethodSecurityService.class);
		service.manyAnnotations(Mono.just(new ArrayList<>(Arrays.asList("harold", "jonathan", "tim", "bo")))).block();
		verify(expressionHandler, times(4)).createEvaluationContext(any(Authentication.class), any());
	}

	// gh-15721
	@Test
	@WithMockUser(roles = "uid")
	public void methodWhenMetaAnnotationPropertiesHasClassProperties() {
		this.spring.register(MetaAnnotationPlaceholderConfig.class).autowire();
		MetaAnnotationService service = this.spring.getContext().getBean(MetaAnnotationService.class);
		assertThat(service.getIdPath("uid").block()).isEqualTo("uid");
	}

	@Configuration
	@EnableReactiveMethodSecurity
	static class MethodSecurityServiceEnabledConfig {

		@Bean
		ReactiveMethodSecurityService methodSecurityService() {
			return new ReactiveMethodSecurityServiceImpl();
		}

	}

	@Configuration
	@EnableReactiveMethodSecurity
	static class CustomMethodSecurityExpressionHandlerConfig {

		private final MethodSecurityExpressionHandler expressionHandler = spy(
				new DefaultMethodSecurityExpressionHandler());

		@Bean
		MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
			return this.expressionHandler;
		}

	}

	@Configuration
	static class PermissionEvaluatorConfig {

		@Bean
		static PermissionEvaluator permissionEvaluator() {
			return mock(PermissionEvaluator.class);
		}

		@Bean
		@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
		static DefaultMethodSecurityExpressionHandler methodSecurityExpressionHandler(
				PermissionEvaluator permissionEvaluator) {
			DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
			handler.setPermissionEvaluator(permissionEvaluator);
			return handler;
		}

	}

	@Configuration
	@EnableReactiveMethodSecurity
	static class LegacyMetaAnnotationPlaceholderConfig {

		@Bean
		PrePostTemplateDefaults methodSecurityDefaults() {
			return new PrePostTemplateDefaults();
		}

		@Bean
		MetaAnnotationService metaAnnotationService() {
			return new MetaAnnotationService();
		}

	}

	@Configuration
	@EnableReactiveMethodSecurity
	static class MetaAnnotationPlaceholderConfig {

		@Bean
		AnnotationTemplateExpressionDefaults methodSecurityDefaults() {
			return new AnnotationTemplateExpressionDefaults();
		}

		@Bean
		MetaAnnotationService metaAnnotationService() {
			return new MetaAnnotationService();
		}

	}

	static class MetaAnnotationService {

		@RequireRole(role = "#role")
		Mono<Boolean> hasRole(String role) {
			return Mono.just(true);
		}

		@RequireRole(role = "'USER'")
		Mono<Boolean> hasUserRole() {
			return Mono.just(true);
		}

		@PreAuthorize("hasRole({role})")
		Mono<Void> placeholdersOnlyResolvedByMetaAnnotations() {
			return Mono.empty();
		}

		@HasClaim(claim = "message:read", roles = { "'ADMIN'" })
		Mono<String> readMessage() {
			return Mono.just("message");
		}

		@ResultStartsWith("dave")
		Mono<String> startsWithDave(String value) {
			return Mono.just(value);
		}

		@ParameterContains("dave")
		Flux<String> parametersContainDave(Flux<String> list) {
			return list;
		}

		@ResultContains("dave")
		Flux<String> resultsContainDave(Flux<String> list) {
			return list;
		}

		@RestrictedAccess(entityClass = EntityClass.class)
		Mono<String> getIdPath(String id) {
			return Mono.just(id);
		}

	}

	@Retention(RetentionPolicy.RUNTIME)
	@PreAuthorize("hasRole({idPath})")
	@interface RestrictedAccess {

		String idPath() default "#id";

		Class<?> entityClass();

		String[] recipes() default {};

	}

	static class EntityClass {

	}

	@Retention(RetentionPolicy.RUNTIME)
	@PreAuthorize("hasRole({role})")
	@interface RequireRole {

		String role();

	}

	@Retention(RetentionPolicy.RUNTIME)
	@PreAuthorize("hasAuthority('SCOPE_{claim}') || hasAnyRole({roles})")
	@interface HasClaim {

		String claim();

		String[] roles() default {};

	}

	@Retention(RetentionPolicy.RUNTIME)
	@PostAuthorize("returnObject.startsWith('{value}')")
	@interface ResultStartsWith {

		String value();

	}

	@Retention(RetentionPolicy.RUNTIME)
	@PreFilter("filterObject.contains('{value}')")
	@interface ParameterContains {

		String value();

	}

	@Retention(RetentionPolicy.RUNTIME)
	@PostFilter("filterObject.contains('{value}')")
	@interface ResultContains {

		String value();

	}

	@EnableReactiveMethodSecurity
	@Configuration
	public static class AuthorizeResultConfig {

		@Bean
		@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
		static Customizer<AuthorizationAdvisorProxyFactory> skipValueTypes() {
			return (f) -> f.setTargetVisitor(AuthorizationAdvisorProxyFactory.TargetVisitor.defaultsSkipValueTypes());
		}

		@Bean
		FlightRepository flights() {
			FlightRepository flights = new FlightRepository();
			Flight one = new Flight("1", 35000d, 35);
			one.board(Flux.just("Marie Curie", "Kevin Mitnick", "Ada Lovelace")).block();
			flights.save(one).block();
			Flight two = new Flight("2", 32000d, 72);
			two.board(Flux.just("Albert Einstein")).block();
			flights.save(two).block();
			return flights;
		}

		@Bean
		static MethodSecurityExpressionHandler expressionHandler() {
			RoleHierarchy hierarchy = RoleHierarchyImpl.withRolePrefix("")
				.role("airplane:read")
				.implies("seating:read")
				.build();
			DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
			expressionHandler.setRoleHierarchy(hierarchy);
			return expressionHandler;
		}

		@Bean
		Authz authz() {
			return new Authz();
		}

		public static class Authz {

			public Mono<Boolean> isNotKevinMitnick(Passenger passenger) {
				return passenger.getName().map((n) -> !"Kevin Mitnick".equals(n));
			}

		}

	}

	@AuthorizeReturnObject
	static class FlightRepository {

		private final Map<String, Flight> flights = new ConcurrentHashMap<>();

		Flux<Flight> findAll() {
			return Flux.fromIterable(this.flights.values());
		}

		Mono<Flight> findById(String id) {
			return Mono.just(this.flights.get(id));
		}

		Mono<Flight> save(Flight flight) {
			this.flights.put(flight.getId(), flight);
			return Mono.just(flight);
		}

		Mono<Void> remove(String id) {
			this.flights.remove(id);
			return Mono.empty();
		}

	}

	@AuthorizeReturnObject
	static class Flight {

		private final String id;

		private final Double altitude;

		private final Integer seats;

		private final List<Passenger> passengers = new ArrayList<>();

		Flight(String id, Double altitude, Integer seats) {
			this.id = id;
			this.altitude = altitude;
			this.seats = seats;
		}

		String getId() {
			return this.id;
		}

		@PreAuthorize("hasAuthority('airplane:read')")
		Mono<Double> getAltitude() {
			return Mono.just(this.altitude);
		}

		@PreAuthorize("hasAuthority('seating:read')")
		Mono<Integer> getSeats() {
			return Mono.just(this.seats);
		}

		@PostAuthorize("hasAuthority('seating:read')")
		@PostFilter("@authz.isNotKevinMitnick(filterObject)")
		Flux<Passenger> getPassengers() {
			return Flux.fromIterable(this.passengers);
		}

		@PreAuthorize("hasAuthority('seating:read')")
		@PreFilter("filterObject.contains(' ')")
		Mono<Void> board(Flux<String> passengers) {
			return passengers.doOnNext((passenger) -> this.passengers.add(new Passenger(passenger))).then(Mono.empty());
		}

	}

	public static class Passenger {

		String name;

		public Passenger(String name) {
			this.name = name;
		}

		@PreAuthorize("hasAuthority('airplane:read')")
		public Mono<String> getName() {
			return Mono.just(this.name);
		}

	}

	abstract static class AbstractClassWithNoAnnotations {

		Mono<String> method() {
			return Mono.just("ok");
		}

	}

	@PreAuthorize("denyAll()")
	@Secured("DENIED")
	@DenyAll
	static class ClassInheritingAbstractClassWithNoAnnotations extends AbstractClassWithNoAnnotations {

	}

	@EnableReactiveMethodSecurity
	static class AbstractClassConfig {

		@Bean
		ClassInheritingAbstractClassWithNoAnnotations inheriting() {
			return new ClassInheritingAbstractClassWithNoAnnotations();
		}

	}

	@Configuration
	@EnableReactiveMethodSecurity
	static class AspectJAwareAutoProxyAndFactoryBeansConfig {

		@Bean
		static BeanDefinitionRegistryPostProcessor beanDefinitionRegistryPostProcessor() {
			return AopConfigUtils::registerAspectJAnnotationAutoProxyCreatorIfNecessary;
		}

		@Component
		static class MyFactoryBean implements FactoryBean<Object> {

			@Override
			public Object getObject() throws Exception {
				return new Object();
			}

			@Override
			public Class<?> getObjectType() {
				return Object.class;
			}

		}

	}

}
