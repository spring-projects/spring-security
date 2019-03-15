/*
 * Copyright 2002-2017 the original author or authors.
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

import org.springframework.core.MethodParameter;
import org.springframework.core.ReactiveAdapter;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.expression.BeanResolver;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.BindingContext;
import org.springframework.web.reactive.result.method.HandlerMethodArgumentResolverSupport;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.lang.annotation.Annotation;

/**
 * Resolves the Authentication
 * @author Rob Winch
 * @since 5.0
 */
public class AuthenticationPrincipalArgumentResolver extends HandlerMethodArgumentResolverSupport {

	private ExpressionParser parser = new SpelExpressionParser();

	private BeanResolver beanResolver;

	public AuthenticationPrincipalArgumentResolver(ReactiveAdapterRegistry adapterRegistry) {
		super(adapterRegistry);
	}

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		return findMethodAnnotation(AuthenticationPrincipal.class, parameter) != null;
	}

	@Override
	public Mono<Object> resolveArgument(MethodParameter parameter, BindingContext bindingContext,
			ServerWebExchange exchange) {
		ReactiveAdapter adapter = getAdapterRegistry().getAdapter(parameter.getParameterType());
		return exchange.getPrincipal()
			.ofType(Authentication.class)
			.flatMap( a -> {
				Object p = resolvePrincipal(parameter, a.getPrincipal());
				Mono<Object> principal = Mono.justOrEmpty(p);
				return adapter == null ? principal : Mono.just(adapter.fromPublisher(principal));
			});
	}

	private Object resolvePrincipal(MethodParameter parameter, Object principal) {
		AuthenticationPrincipal authPrincipal = findMethodAnnotation(
			AuthenticationPrincipal.class, parameter);

		String expressionToParse = authPrincipal.expression();
		if (StringUtils.hasLength(expressionToParse)) {
			StandardEvaluationContext context = new StandardEvaluationContext();
			context.setRootObject(principal);
			context.setVariable("this", principal);
			context.setBeanResolver(beanResolver);

			Expression expression = this.parser.parseExpression(expressionToParse);
			principal = expression.getValue(context);
		}

		return principal;
	}

	/**
	 * Obtains the specified {@link Annotation} on the specified {@link MethodParameter}.
	 *
	 * @param annotationClass the class of the {@link Annotation} to find on the
	 * {@link MethodParameter}
	 * @param parameter the {@link MethodParameter} to search for an {@link Annotation}
	 * @return the {@link Annotation} that was found or null.
	 */
	private <T extends Annotation> T findMethodAnnotation(Class<T> annotationClass,
			MethodParameter parameter) {
		T annotation = parameter.getParameterAnnotation(annotationClass);
		if (annotation != null) {
			return annotation;
		}
		Annotation[] annotationsToSearch = parameter.getParameterAnnotations();
		for (Annotation toSearch : annotationsToSearch) {
			annotation = AnnotationUtils.findAnnotation(toSearch.annotationType(),
				annotationClass);
			if (annotation != null) {
				return annotation;
			}
		}
		return null;
	}

}
