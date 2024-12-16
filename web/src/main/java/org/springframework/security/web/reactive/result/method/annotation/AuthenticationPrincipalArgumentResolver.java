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

package org.springframework.security.web.reactive.result.method.annotation;

import java.lang.annotation.Annotation;

import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import org.springframework.core.MethodParameter;
import org.springframework.core.ReactiveAdapter;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.core.ResolvableType;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.annotation.MergedAnnotations;
import org.springframework.expression.BeanResolver;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.annotation.SecurityAnnotationScanner;
import org.springframework.security.core.annotation.SecurityAnnotationScanners;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.BindingContext;
import org.springframework.web.reactive.result.method.HandlerMethodArgumentResolverSupport;
import org.springframework.web.server.ServerWebExchange;

/**
 * Resolves the Authentication
 *
 * @author Rob Winch
 * @author DingHao
 * @since 5.0
 */
public class AuthenticationPrincipalArgumentResolver extends HandlerMethodArgumentResolverSupport {

	private ExpressionParser parser = new SpelExpressionParser();

	private final Class<AuthenticationPrincipal> annotationType = AuthenticationPrincipal.class;

	private SecurityAnnotationScanner<AuthenticationPrincipal> scanner = SecurityAnnotationScanners
		.requireUnique(this.annotationType);

	private boolean useAnnotationTemplate = false;

	private BeanResolver beanResolver;

	public AuthenticationPrincipalArgumentResolver(ReactiveAdapterRegistry adapterRegistry) {
		super(adapterRegistry);
	}

	/**
	 * Sets the {@link BeanResolver} to be used on the expressions
	 * @param beanResolver the {@link BeanResolver} to use
	 */
	public void setBeanResolver(BeanResolver beanResolver) {
		this.beanResolver = beanResolver;
	}

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		return findMethodAnnotation(parameter) != null;
	}

	@Override
	public Mono<Object> resolveArgument(MethodParameter parameter, BindingContext bindingContext,
			ServerWebExchange exchange) {
		ReactiveAdapter adapter = getAdapterRegistry().getAdapter(parameter.getParameterType());
		return ReactiveSecurityContextHolder.getContext()
			.map(SecurityContext::getAuthentication)
			.flatMap((authentication) -> {
				Mono<Object> principal = Mono.justOrEmpty(resolvePrincipal(parameter, authentication.getPrincipal()));
				return (adapter != null) ? Mono.just(adapter.fromPublisher(principal)) : principal;
			});
	}

	private Object resolvePrincipal(MethodParameter parameter, Object principal) {
		AuthenticationPrincipal annotation = findMethodAnnotation(parameter);
		String expressionToParse = annotation.expression();
		if (StringUtils.hasLength(expressionToParse)) {
			StandardEvaluationContext context = new StandardEvaluationContext();
			context.setRootObject(principal);
			context.setVariable("this", principal);
			context.setBeanResolver(this.beanResolver);
			Expression expression = this.parser.parseExpression(expressionToParse);
			principal = expression.getValue(context);
		}
		if (isInvalidType(parameter, principal)) {
			if (annotation.errorOnInvalidType()) {
				throw new ClassCastException(principal + " is not assignable to " + parameter.getParameterType());
			}
			return null;
		}
		return principal;
	}

	private boolean isInvalidType(MethodParameter parameter, Object principal) {
		if (principal == null) {
			return false;
		}
		Class<?> typeToCheck = parameter.getParameterType();
		boolean isParameterPublisher = Publisher.class.isAssignableFrom(parameter.getParameterType());
		if (isParameterPublisher) {
			ResolvableType resolvableType = ResolvableType.forMethodParameter(parameter);
			Class<?> genericType = resolvableType.resolveGeneric(0);
			if (genericType == null) {
				return false;
			}
			typeToCheck = genericType;
		}
		return !ClassUtils.isAssignable(typeToCheck, principal.getClass());
	}

	/**
	 * Configure AuthenticationPrincipal template resolution
	 * <p>
	 * By default, this value is <code>null</code>, which indicates that templates should
	 * not be resolved.
	 * @param templateDefaults - whether to resolve AuthenticationPrincipal templates
	 * parameters
	 * @since 6.4
	 */
	public void setTemplateDefaults(AnnotationTemplateExpressionDefaults templateDefaults) {
		this.useAnnotationTemplate = templateDefaults != null;
		this.scanner = SecurityAnnotationScanners.requireUnique(AuthenticationPrincipal.class, templateDefaults);
	}

	/**
	 * Obtains the specified {@link Annotation} on the specified {@link MethodParameter}.
	 * {@link MethodParameter}
	 * @param parameter the {@link MethodParameter} to search for an {@link Annotation}
	 * @return the {@link Annotation} that was found or null.
	 */
	private AuthenticationPrincipal findMethodAnnotation(MethodParameter parameter) {
		if (this.useAnnotationTemplate) {
			return this.scanner.scan(parameter.getParameter());
		}
		AuthenticationPrincipal annotation = parameter.getParameterAnnotation(this.annotationType);
		if (annotation != null) {
			return annotation;
		}
		Annotation[] annotationsToSearch = parameter.getParameterAnnotations();
		for (Annotation toSearch : annotationsToSearch) {
			annotation = AnnotationUtils.findAnnotation(toSearch.annotationType(), this.annotationType);
			if (annotation != null) {
				return MergedAnnotations.from(toSearch).get(this.annotationType).synthesize();
			}
		}
		return null;
	}

}
