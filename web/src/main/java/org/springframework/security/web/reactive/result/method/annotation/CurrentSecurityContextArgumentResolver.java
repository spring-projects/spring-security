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
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.annotation.SecurityAnnotationScanner;
import org.springframework.security.core.annotation.SecurityAnnotationScanners;
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
 * @author DingHao
 * @since 5.2
 */
public class CurrentSecurityContextArgumentResolver extends HandlerMethodArgumentResolverSupport {

	private ExpressionParser parser = new SpelExpressionParser();

	private final Class<CurrentSecurityContext> annotationType = CurrentSecurityContext.class;

	private SecurityAnnotationScanner<CurrentSecurityContext> scanner = SecurityAnnotationScanners
		.requireUnique(this.annotationType);

	private boolean useAnnotationTemplate = false;

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
	 * Configure CurrentSecurityContext template resolution
	 * <p>
	 * By default, this value is <code>null</code>, which indicates that templates should
	 * not be resolved.
	 * @param templateDefaults - whether to resolve CurrentSecurityContext templates
	 * parameters
	 * @since 6.4
	 */
	public void setTemplateDefaults(AnnotationTemplateExpressionDefaults templateDefaults) {
		this.useAnnotationTemplate = templateDefaults != null;
		this.scanner = SecurityAnnotationScanners.requireUnique(CurrentSecurityContext.class, templateDefaults);
	}

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		return isMonoSecurityContext(parameter) || findMethodAnnotation(parameter) != null;
	}

	private boolean isMonoSecurityContext(MethodParameter parameter) {
		boolean isParameterPublisher = Publisher.class.isAssignableFrom(parameter.getParameterType());
		if (isParameterPublisher) {
			ResolvableType resolvableType = ResolvableType.forMethodParameter(parameter);
			Class<?> genericType = resolvableType.resolveGeneric(0);
			if (genericType == null) {
				return false;
			}
			return SecurityContext.class.isAssignableFrom(genericType);
		}
		return false;
	}

	@Override
	public Mono<Object> resolveArgument(MethodParameter parameter, BindingContext bindingContext,
			ServerWebExchange exchange) {
		ReactiveAdapter adapter = getAdapterRegistry().getAdapter(parameter.getParameterType());
		Mono<SecurityContext> reactiveSecurityContext = ReactiveSecurityContextHolder.getContext();
		if (reactiveSecurityContext == null) {
			return null;
		}
		return reactiveSecurityContext.flatMap((securityContext) -> {
			Mono<Object> resolvedSecurityContext = Mono.justOrEmpty(resolveSecurityContext(parameter, securityContext));
			return (adapter != null) ? Mono.just(adapter.fromPublisher(resolvedSecurityContext))
					: resolvedSecurityContext;
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
		CurrentSecurityContext annotation = findMethodAnnotation(parameter);
		if (annotation != null) {
			return resolveSecurityContextFromAnnotation(annotation, parameter, securityContext);
		}
		return securityContext;
	}

	private Object resolveSecurityContextFromAnnotation(CurrentSecurityContext annotation, MethodParameter parameter,
			Object securityContext) {
		Object securityContextResult = securityContext;
		String expressionToParse = annotation.expression();
		if (StringUtils.hasLength(expressionToParse)) {
			StandardEvaluationContext context = new StandardEvaluationContext();
			context.setRootObject(securityContext);
			context.setVariable("this", securityContext);
			context.setBeanResolver(this.beanResolver);
			Expression expression = this.parser.parseExpression(expressionToParse);
			securityContextResult = expression.getValue(context);
		}
		if (isInvalidType(parameter, securityContextResult)) {
			if (annotation.errorOnInvalidType()) {
				throw new ClassCastException(
						securityContextResult + " is not assignable to " + parameter.getParameterType());
			}
			return null;
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
	 * @param parameter the {@link MethodParameter} to search for an {@link Annotation}
	 * @return the {@link Annotation} that was found or null.
	 */
	private CurrentSecurityContext findMethodAnnotation(MethodParameter parameter) {
		if (this.useAnnotationTemplate) {
			return this.scanner.scan(parameter.getParameter());
		}
		CurrentSecurityContext annotation = parameter.getParameterAnnotation(this.annotationType);
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
