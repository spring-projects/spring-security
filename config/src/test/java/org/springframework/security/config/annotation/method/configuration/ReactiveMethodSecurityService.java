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

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.aopalliance.intercept.MethodInvocation;
import reactor.core.publisher.Mono;

import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.method.MethodAuthorizationDeniedHandler;
import org.springframework.security.authorization.method.MethodAuthorizationDeniedPostProcessor;
import org.springframework.security.authorization.method.MethodInvocationResult;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;

/**
 * @author Rob Winch
 */
@ReactiveMethodSecurityService.Mask("classmask")
public interface ReactiveMethodSecurityService {

	@PreAuthorize(value = "hasRole('ADMIN')", handlerClass = StarMaskingHandler.class)
	Mono<String> preAuthorizeGetCardNumberIfAdmin(String cardNumber);

	@PreAuthorize(value = "hasRole('ADMIN')", handlerClass = StartMaskingHandlerChild.class)
	Mono<String> preAuthorizeWithHandlerChildGetCardNumberIfAdmin(String cardNumber);

	@PreAuthorize(value = "hasRole('ADMIN')", handlerClass = StarMaskingHandler.class)
	Mono<String> preAuthorizeThrowAccessDeniedManually();

	@PostAuthorize(value = "hasRole('ADMIN')", postProcessorClass = CardNumberMaskingPostProcessor.class)
	Mono<String> postAuthorizeGetCardNumberIfAdmin(String cardNumber);

	@PostAuthorize(value = "hasRole('ADMIN')", postProcessorClass = PostMaskingPostProcessor.class)
	Mono<String> postAuthorizeThrowAccessDeniedManually();

	@PreAuthorize(value = "denyAll()", handlerClass = MaskAnnotationHandler.class)
	@Mask("methodmask")
	Mono<String> preAuthorizeDeniedMethodWithMaskAnnotation();

	@PreAuthorize(value = "denyAll()", handlerClass = MaskAnnotationHandler.class)
	Mono<String> preAuthorizeDeniedMethodWithNoMaskAnnotation();

	@NullDenied(role = "ADMIN")
	Mono<String> postAuthorizeDeniedWithNullDenied();

	@PostAuthorize(value = "denyAll()", postProcessorClass = MaskAnnotationPostProcessor.class)
	@Mask("methodmask")
	Mono<String> postAuthorizeDeniedMethodWithMaskAnnotation();

	@PostAuthorize(value = "denyAll()", postProcessorClass = MaskAnnotationPostProcessor.class)
	Mono<String> postAuthorizeDeniedMethodWithNoMaskAnnotation();

	@PreAuthorize(value = "hasRole('ADMIN')", handlerClass = MaskAnnotationHandler.class)
	@Mask(expression = "@myMasker.getMask()")
	Mono<String> preAuthorizeWithMaskAnnotationUsingBean();

	@PostAuthorize(value = "hasRole('ADMIN')", postProcessorClass = MaskAnnotationPostProcessor.class)
	@Mask(expression = "@myMasker.getMask(returnObject)")
	Mono<String> postAuthorizeWithMaskAnnotationUsingBean();

	class StarMaskingHandler implements MethodAuthorizationDeniedHandler {

		@Override
		public Object handle(MethodInvocation methodInvocation, AuthorizationResult result) {
			return "***";
		}

	}

	class StartMaskingHandlerChild extends StarMaskingHandler {

		@Override
		public Object handle(MethodInvocation methodInvocation, AuthorizationResult result) {
			return super.handle(methodInvocation, result) + "-child";
		}

	}

	class MaskAnnotationHandler implements MethodAuthorizationDeniedHandler {

		MaskValueResolver maskValueResolver;

		MaskAnnotationHandler(ApplicationContext context) {
			this.maskValueResolver = new MaskValueResolver(context);
		}

		@Override
		public Object handle(MethodInvocation methodInvocation, AuthorizationResult result) {
			Mask mask = AnnotationUtils.getAnnotation(methodInvocation.getMethod(), Mask.class);
			if (mask == null) {
				mask = AnnotationUtils.getAnnotation(methodInvocation.getMethod().getDeclaringClass(), Mask.class);
			}
			return this.maskValueResolver.resolveValue(mask, methodInvocation, null);
		}

	}

	class MaskAnnotationPostProcessor implements MethodAuthorizationDeniedPostProcessor {

		MaskValueResolver maskValueResolver;

		MaskAnnotationPostProcessor(ApplicationContext context) {
			this.maskValueResolver = new MaskValueResolver(context);
		}

		@Override
		public Object postProcessResult(MethodInvocationResult methodInvocationResult,
				AuthorizationResult authorizationResult) {
			MethodInvocation mi = methodInvocationResult.getMethodInvocation();
			Mask mask = AnnotationUtils.getAnnotation(mi.getMethod(), Mask.class);
			if (mask == null) {
				mask = AnnotationUtils.getAnnotation(mi.getMethod().getDeclaringClass(), Mask.class);
			}
			return this.maskValueResolver.resolveValue(mask, mi, methodInvocationResult.getResult());
		}

	}

	class MaskValueResolver {

		DefaultMethodSecurityExpressionHandler expressionHandler;

		MaskValueResolver(ApplicationContext context) {
			this.expressionHandler = new DefaultMethodSecurityExpressionHandler();
			this.expressionHandler.setApplicationContext(context);
		}

		Mono<String> resolveValue(Mask mask, MethodInvocation mi, Object returnObject) {
			if (StringUtils.hasText(mask.value())) {
				return Mono.just(mask.value());
			}
			Expression expression = this.expressionHandler.getExpressionParser().parseExpression(mask.expression());
			EvaluationContext evaluationContext = this.expressionHandler
				.createEvaluationContext(() -> SecurityContextHolder.getContext().getAuthentication(), mi);
			if (returnObject != null) {
				this.expressionHandler.setReturnObject(returnObject, evaluationContext);
			}
			return Mono.just(expression.getValue(evaluationContext, String.class));
		}

	}

	class PostMaskingPostProcessor implements MethodAuthorizationDeniedPostProcessor {

		@Override
		public Object postProcessResult(MethodInvocationResult contextObject, AuthorizationResult result) {
			return "***";
		}

	}

	class CardNumberMaskingPostProcessor implements MethodAuthorizationDeniedPostProcessor {

		static String MASK = "****-****-****-";

		@Override
		public Object postProcessResult(MethodInvocationResult contextObject, AuthorizationResult result) {
			String cardNumber = (String) contextObject.getResult();
			return MASK + cardNumber.substring(cardNumber.length() - 4);
		}

	}

	class NullPostProcessor implements MethodAuthorizationDeniedPostProcessor {

		@Override
		public Object postProcessResult(MethodInvocationResult methodInvocationResult,
				AuthorizationResult authorizationResult) {
			return null;
		}

	}

	@Target({ ElementType.METHOD, ElementType.TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	@Inherited
	@interface Mask {

		String value() default "";

		String expression() default "";

	}

	@Target({ ElementType.METHOD, ElementType.TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	@Inherited
	@PostAuthorize(value = "hasRole('{value}')", postProcessorClass = NullPostProcessor.class)
	@interface NullDenied {

		String role();

	}

}
