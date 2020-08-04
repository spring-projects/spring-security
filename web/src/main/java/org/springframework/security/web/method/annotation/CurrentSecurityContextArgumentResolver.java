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

package org.springframework.security.web.method.annotation;

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
 * Allows resolving the {@link SecurityContext} using the {@link CurrentSecurityContext}
 * annotation. For example, the following {@link Controller}:
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
 * Will resolve the {@link SecurityContext} argument using
 * {@link SecurityContextHolder#getContext()} from the {@link SecurityContextHolder}. If
 * the {@link SecurityContext} is {@code null}, it will return {@code null}. If the types
 * do not match, {@code null} will be returned unless
 * {@link CurrentSecurityContext#errorOnInvalidType()} is {@code true} in which case a
 * {@link ClassCastException} will be thrown.
 * </p>
 *
 * @author Dan Zheng
 * @since 5.2
 */
public final class CurrentSecurityContextArgumentResolver implements HandlerMethodArgumentResolver {

	private ExpressionParser parser = new SpelExpressionParser();

	private BeanResolver beanResolver;

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		return findMethodAnnotation(CurrentSecurityContext.class, parameter) != null;
	}

	@Override
	public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
			NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
		SecurityContext securityContext = SecurityContextHolder.getContext();
		if (securityContext == null) {
			return null;
		}
		Object securityContextResult = securityContext;
		CurrentSecurityContext annotation = findMethodAnnotation(CurrentSecurityContext.class, parameter);
		String expressionToParse = annotation.expression();
		if (StringUtils.hasLength(expressionToParse)) {
			StandardEvaluationContext context = new StandardEvaluationContext();
			context.setRootObject(securityContext);
			context.setVariable("this", securityContext);
			Expression expression = this.parser.parseExpression(expressionToParse);
			securityContextResult = expression.getValue(context);
		}
		if (securityContextResult != null
				&& !parameter.getParameterType().isAssignableFrom(securityContextResult.getClass())) {
			if (annotation.errorOnInvalidType()) {
				throw new ClassCastException(
						securityContextResult + " is not assignable to " + parameter.getParameterType());
			}
			return null;
		}
		return securityContextResult;
	}

	/**
	 * Set the {@link BeanResolver} to be used on the expressions
	 * @param beanResolver the {@link BeanResolver} to use
	 */
	public void setBeanResolver(BeanResolver beanResolver) {
		Assert.notNull(beanResolver, "beanResolver cannot be null");
		this.beanResolver = beanResolver;
	}

	/**
	 * Obtain the specified {@link Annotation} on the specified {@link MethodParameter}.
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
