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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.method.PrePostTemplateDefaults;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
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

	@Configuration
	@EnableReactiveMethodSecurity
	static class MethodSecurityServiceEnabledConfig {

		@Bean
		ReactiveMethodSecurityService methodSecurityService() {
			return new ReactiveMethodSecurityServiceImpl();
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

}
