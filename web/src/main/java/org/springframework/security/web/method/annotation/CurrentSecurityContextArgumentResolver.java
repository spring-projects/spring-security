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

package org.springframework.security.web.method.annotation;

import java.lang.annotation.Annotation;

import org.springframework.core.MethodParameter;
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
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
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
 * @author DingHao
 * @since 5.2
 */
public final class CurrentSecurityContextArgumentResolver implements HandlerMethodArgumentResolver {

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	private ExpressionParser parser = new SpelExpressionParser();

	private final Class<CurrentSecurityContext> annotationType = CurrentSecurityContext.class;

	private SecurityAnnotationScanner<CurrentSecurityContext> scanner = SecurityAnnotationScanners
		.requireUnique(this.annotationType);

	private boolean useAnnotationTemplate = false;

	private BeanResolver beanResolver;

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		return SecurityContext.class.isAssignableFrom(parameter.getParameterType())
				|| findMethodAnnotation(parameter) != null;
	}

	@Override
	public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
			NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
		SecurityContext securityContext = this.securityContextHolderStrategy.getContext();
		if (securityContext == null) {
			return null;
		}
		CurrentSecurityContext annotation = findMethodAnnotation(parameter);
		if (annotation != null) {
			return resolveSecurityContextFromAnnotation(parameter, annotation, securityContext);
		}

		return securityContext;
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 *
	 * @since 5.8
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
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

	private Object resolveSecurityContextFromAnnotation(MethodParameter parameter, CurrentSecurityContext annotation,
			SecurityContext securityContext) {
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
	 * Obtain the specified {@link Annotation} on the specified {@link MethodParameter}.
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
