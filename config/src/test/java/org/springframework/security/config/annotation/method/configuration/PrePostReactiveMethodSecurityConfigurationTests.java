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
import reactor.test.StepVerifier;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;

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

}
