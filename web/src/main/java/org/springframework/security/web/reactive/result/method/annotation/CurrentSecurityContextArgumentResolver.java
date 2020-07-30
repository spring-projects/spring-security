/*
 * Copyright 2002-2019 the original author or authors.
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
import org.springframework.expression.BeanResolver;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.BindingContext;
import org.springframework.web.reactive.result.method.HandlerMethodArgumentResolverSupport;
import org.springframework.web.server.ServerWebExchange;

/**
 * Resolves the {@link SecurityContext}
 *
 * @author Dan Zheng
 * @since 5.2
 */
public class CurrentSecurityContextArgumentResolver extends HandlerMethodArgumentResolverSupport {

	private ExpressionParser parser = new SpelExpressionParser();

	private BeanResolver beanResolver;

	public CurrentSecurityContextArgumentResolver(ReactiveAdapterRegistry adapterRegistry) {
		super(adapterRegistry);
	}

	/**
	 * Sets the {@link BeanResolver} to be used on the expressions
	 * @param beanResolver the {@link BeanResolver} to use
	 */
	public void setBeanResolver(BeanResolver beanResolver) {
		Assert.notNull(beanResolver, "beanResolver cannot be null");
		this.beanResolver = beanResolver;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		return findMethodAnnotation(CurrentSecurityContext.class, parameter) != null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Mono<Object> resolveArgument(MethodParameter parameter, BindingContext bindingContext,
			ServerWebExchange exchange) {
		ReactiveAdapter adapter = getAdapterRegistry().getAdapter(parameter.getParameterType());
		Mono<SecurityContext> reactiveSecurityContext = ReactiveSecurityContextHolder.getContext();
		if (reactiveSecurityContext == null) {
			return null;
		}
		return reactiveSecurityContext.flatMap((a) -> {
			Object p = resolveSecurityContext(parameter, a);
			Mono<Object> o = Mono.justOrEmpty(p);
			return adapter == null ? o : Mono.just(adapter.fromPublisher(o));
		});

	}

	/**
	 * resolve the expression from {@link CurrentSecurityContext} annotation to get the
	 * value.
	 * @param parameter the method parameter.
	 * @param securityContext the security context.
	 * @return the resolved object from expression.
	 */
	private Object resolveSecurityContext(MethodParameter parameter, SecurityContext securityContext) {
		CurrentSecurityContext securityContextAnnotation = findMethodAnnotation(CurrentSecurityContext.class,
				parameter);

		Object securityContextResult = securityContext;

		String expressionToParse = securityContextAnnotation.expression();
		if (StringUtils.hasLength(expressionToParse)) {
			StandardEvaluationContext context = new StandardEvaluationContext();
			context.setRootObject(securityContext);
			context.setVariable("this", securityContext);
			context.setBeanResolver(this.beanResolver);

			Expression expression = this.parser.parseExpression(expressionToParse);
			securityContextResult = expression.getValue(context);
		}

		if (isInvalidType(parameter, securityContextResult)) {
			if (securityContextAnnotation.errorOnInvalidType()) {
				throw new ClassCastException(
						securityContextResult + " is not assignable to " + parameter.getParameterType());
			}
			else {
				return null;
			}
		}

		return securityContextResult;
	}

	/**
	 * check if the retrieved value match with the parameter type.
	 * @param parameter the method parameter.
	 * @param reactiveSecurityContext the security context.
	 * @return true = is not invalid type.
	 */
	private boolean isInvalidType(MethodParameter parameter, Object reactiveSecurityContext) {
		if (reactiveSecurityContext == null) {
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
		return !typeToCheck.isAssignableFrom(reactiveSecurityContext.getClass());
	}

	/**
	 * Obtains the specified {@link Annotation} on the specified {@link MethodParameter}.
	 * @param annotationClass the class of the {@link Annotation} to find on the
	 * {@link MethodParameter}
	 * @param parameter the {@link MethodParameter} to search for an {@link Annotation}
	 * @return the {@link Annotation} that was found or null.
	 */
	private <T extends Annotation> T findMethodAnnotation(Class<T> annotationClass, MethodParameter parameter) {
		T annotation = parameter.getParameterAnnotation(annotationClass);
		if (annotation != null) {
			return annotation;
		}
		Annotation[] annotationsToSearch = parameter.getParameterAnnotations();
		for (Annotation toSearch : annotationsToSearch) {
			annotation = AnnotationUtils.findAnnotation(toSearch.annotationType(), annotationClass);
			if (annotation != null) {
				return annotation;
			}
		}
		return null;
	}

}
