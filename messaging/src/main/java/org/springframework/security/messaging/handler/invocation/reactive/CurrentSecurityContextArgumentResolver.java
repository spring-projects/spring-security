/*
 * Copyright 2019 the original author or authors.
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

package org.springframework.security.messaging.handler.invocation.reactive;

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
import org.springframework.messaging.Message;
import org.springframework.messaging.handler.invocation.reactive.HandlerMethodArgumentResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.annotation.SecurityAnnotationScanner;
import org.springframework.security.core.annotation.SecurityAnnotationScanners;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Allows resolving the {@link Authentication#getPrincipal()} using the
 * {@link CurrentSecurityContext} annotation. For example, the following
 * {@link Controller}:
 *
 * <pre>
 * &#64;Controller
 * public class MyController {
 *     &#64;MessageMapping("/im")
 *     public void im(@CurrentSecurityContext SecurityContext context) {
 *         // do something with context
 *     }
 * }
 * </pre>
 *
 * <p>
 * Will resolve the SecurityContext argument using the
 * {@link ReactiveSecurityContextHolder}. If the {@link SecurityContext} is empty, it will
 * return null. If the types do not match, null will be returned unless
 * {@link CurrentSecurityContext#errorOnInvalidType()} is true in which case a
 * {@link ClassCastException} will be thrown.
 *
 * <p>
 * Alternatively, users can create a custom meta annotation as shown below:
 *
 * <pre>
 * &#064;Target({ ElementType.PARAMETER })
 * &#064;Retention(RetentionPolicy.RUNTIME)
 * &#064;CurrentSecurityContext(expression = "authentication?.principal")
 * public @interface CurrentUser {
 * }
 * </pre>
 *
 * <p>
 * The custom annotation can then be used instead. For example:
 *
 * <pre>
 * &#64;Controller
 * public class MyController {
 *     &#64;MessageMapping("/im")
 *     public void im(@CurrentUser CustomUser customUser) {
 *         // do something with CustomUser
 *     }
 * }
 * </pre>
 *
 * @author Rob Winch
 * @author DingHao
 * @since 5.2
 */
public class CurrentSecurityContextArgumentResolver implements HandlerMethodArgumentResolver {

	private ExpressionParser parser = new SpelExpressionParser();

	private final Class<CurrentSecurityContext> annotationType = CurrentSecurityContext.class;

	private SecurityAnnotationScanner<CurrentSecurityContext> scanner = SecurityAnnotationScanners
		.requireUnique(this.annotationType);

	private boolean useAnnotationTemplate = false;

	private BeanResolver beanResolver;

	private ReactiveAdapterRegistry adapterRegistry = ReactiveAdapterRegistry.getSharedInstance();

	/**
	 * Sets the {@link BeanResolver} to be used on the expressions
	 * @param beanResolver the {@link BeanResolver} to use
	 */
	public void setBeanResolver(BeanResolver beanResolver) {
		this.beanResolver = beanResolver;
	}

	/**
	 * Sets the {@link ReactiveAdapterRegistry} to be used.
	 * @param adapterRegistry the {@link ReactiveAdapterRegistry} to use. Cannot be null.
	 * Default is {@link ReactiveAdapterRegistry#getSharedInstance()}
	 */
	public void setAdapterRegistry(ReactiveAdapterRegistry adapterRegistry) {
		Assert.notNull(adapterRegistry, "adapterRegistry cannot be null");
		this.adapterRegistry = adapterRegistry;
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
	public Mono<Object> resolveArgument(MethodParameter parameter, Message<?> message) {
		ReactiveAdapter adapter = this.adapterRegistry.getAdapter(parameter.getParameterType());
		// @formatter:off
		return ReactiveSecurityContextHolder.getContext()
				.flatMap((securityContext) -> {
					Object sc = resolveSecurityContext(parameter, securityContext);
					Mono<Object> result = Mono.justOrEmpty(sc);
					return (adapter != null) ? Mono.just(adapter.fromPublisher(result)) : result;
				});
		// @formatter:on
	}

	private Object resolveSecurityContext(MethodParameter parameter, Object securityContext) {
		CurrentSecurityContext contextAnno = findMethodAnnotation(parameter);
		if (contextAnno != null) {
			return resolveSecurityContextFromAnnotation(contextAnno, parameter, securityContext);
		}
		return securityContext;
	}

	private Object resolveSecurityContextFromAnnotation(CurrentSecurityContext contextAnno, MethodParameter parameter,
			Object securityContext) {
		String expressionToParse = contextAnno.expression();
		if (StringUtils.hasLength(expressionToParse)) {
			StandardEvaluationContext context = new StandardEvaluationContext();
			context.setRootObject(securityContext);
			context.setVariable("this", securityContext);
			context.setBeanResolver(this.beanResolver);
			Expression expression = this.parser.parseExpression(expressionToParse);
			securityContext = expression.getValue(context);
		}
		if (isInvalidType(parameter, securityContext)) {
			if (contextAnno.errorOnInvalidType()) {
				throw new ClassCastException(securityContext + " is not assignable to " + parameter.getParameterType());
			}
			return null;
		}
		return securityContext;
	}

	private boolean isInvalidType(MethodParameter parameter, Object value) {
		if (value == null) {
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
		return !typeToCheck.isAssignableFrom(value.getClass());
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
