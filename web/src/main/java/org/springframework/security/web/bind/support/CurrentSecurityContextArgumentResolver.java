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
package org.springframework.security.web.bind.support;

import java.lang.annotation.Annotation;

import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.expression.BeanResolver;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * Allows resolving the {@link SecurityContext} using the
 * {@link CurrentSecurityContext} annotation. For example, the following
 * {@link Controller}:
 *
 * <pre>
 * &#64;Controller
 * public class MyController {
 *     &#64;RequestMapping("/im")
 *     public void security(@CurrentSecurityContext SecurityContext context) {
 *         // do something with context
 *     }
 * }
 * </pre>
 *
 * it can also support the spring SPEL expression to get the value from SecurityContext
 * <pre>
 * &#64;Controller
 * public class MyController {
 *     &#64;RequestMapping("/im")
 *     public void security(@CurrentSecurityContext(expression="authentication") Authentication authentication) {
 *         // do something with context
 *     }
 * }
 * </pre>
 *
 * <p>
 * Will resolve the SecurityContext argument using {@link SecurityContextHolder#getContext()} from
 * the {@link SecurityContextHolder}. If the {@link SecurityContext} is null, it will return null.
 * If the types do not match, null will be returned unless
 * {@link CurrentSecurityContext#errorOnInvalidType()} is true in which case a
 * {@link ClassCastException} will be thrown.
 * </p>
 *
 * @author Dan Zheng
 * @since 5.2
 */
public final class CurrentSecurityContextArgumentResolver
		implements HandlerMethodArgumentResolver {

	private ExpressionParser parser = new SpelExpressionParser();

	private BeanResolver beanResolver;
	/**
	 * check if this argument resolve can support the parameter.
	 * @param parameter the method parameter.
	 * @return true = it can support parameter.
	 *
	 * @see
	 * org.springframework.web.method.support.HandlerMethodArgumentResolver#
	 * supportsParameter(org.springframework.core.MethodParameter)
	 */
	public boolean supportsParameter(MethodParameter parameter) {
		return findMethodAnnotation(CurrentSecurityContext.class, parameter) != null;
	}

	/**
	 * resolve the argument to inject into the controller parameter.
	 * @param parameter the method parameter.
	 * @param mavContainer the model and view container.
	 * @param webRequest the web request.
	 * @param binderFactory the web data binder factory.
	 *
	 * @see org.springframework.web.method.support.HandlerMethodArgumentResolver#
	 * resolveArgument (org.springframework.core.MethodParameter,
	 * org.springframework.web.method.support.ModelAndViewContainer,
	 * org.springframework.web.context.request.NativeWebRequest,
	 * org.springframework.web.bind.support.WebDataBinderFactory)
	 */
	public Object resolveArgument(MethodParameter parameter,
				ModelAndViewContainer mavContainer, NativeWebRequest webRequest,
				WebDataBinderFactory binderFactory) {
		SecurityContext securityContext = SecurityContextHolder.getContext();
		if (securityContext == null) {
			return null;
		}
		Object securityContextResult = securityContext;

		CurrentSecurityContext securityContextAnnotation = findMethodAnnotation(
				CurrentSecurityContext.class, parameter);

		String expressionToParse = securityContextAnnotation.expression();
		if (StringUtils.hasLength(expressionToParse)) {
			StandardEvaluationContext context = new StandardEvaluationContext();
			context.setRootObject(securityContext);
			context.setVariable("this", securityContext);

			Expression expression = this.parser.parseExpression(expressionToParse);
			securityContextResult = expression.getValue(context);
		}

		if (securityContextResult != null
				&& !parameter.getParameterType().isAssignableFrom(securityContextResult.getClass())) {
			if (securityContextAnnotation.errorOnInvalidType()) {
				throw new ClassCastException(securityContextResult + " is not assignable to "
						+ parameter.getParameterType());
			}
			else {
				return null;
			}
		}
		return securityContextResult;
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
