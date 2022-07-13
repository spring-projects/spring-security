/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.method;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.springframework.aop.ClassFilter;
import org.springframework.aop.MethodMatcher;
import org.springframework.aop.Pointcut;
import org.springframework.aop.config.AbstractInterceptorDrivenBeanDefinitionDecorator;
import org.springframework.aop.support.AopUtils;
import org.springframework.aop.support.RootClassFilter;
import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionDecorator;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.Elements;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.expression.ExpressionAuthorizationDecision;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;

/**
 * @author Luke Taylor
 * @author Ben Alex
 *
 */
public class InterceptMethodsBeanDefinitionDecorator implements BeanDefinitionDecorator {

	private final InternalAuthorizationManagerInterceptMethodsBeanDefinitionDecorator authorizationManagerDelegate = new InternalAuthorizationManagerInterceptMethodsBeanDefinitionDecorator();

	private final BeanDefinitionDecorator delegate = new InternalInterceptMethodsBeanDefinitionDecorator();

	@Override
	public BeanDefinitionHolder decorate(Node node, BeanDefinitionHolder definition, ParserContext parserContext) {
		if (this.authorizationManagerDelegate.supports(node)) {
			return this.authorizationManagerDelegate.decorate(node, definition, parserContext);
		}
		MethodConfigUtils.registerDefaultMethodAccessManagerIfNecessary(parserContext);
		return this.delegate.decorate(node, definition, parserContext);
	}

	static class InternalAuthorizationManagerInterceptMethodsBeanDefinitionDecorator
			extends AbstractInterceptorDrivenBeanDefinitionDecorator {

		static final String ATT_METHOD = "method";

		static final String ATT_ACCESS = "access";

		private static final String ATT_USE_AUTHORIZATION_MGR = "use-authorization-manager";

		private static final String ATT_AUTHORIZATION_MGR = "authorization-manager-ref";

		private final ClassLoader beanClassLoader = ClassUtils.getDefaultClassLoader();

		@Override
		protected BeanDefinition createInterceptorDefinition(Node node) {
			Element interceptMethodsElt = (Element) node;
			BeanDefinitionBuilder interceptor = BeanDefinitionBuilder
					.rootBeanDefinition(AuthorizationManagerBeforeMethodInterceptor.class);
			interceptor.setAutowireMode(AbstractBeanDefinition.AUTOWIRE_BY_TYPE);
			Map<Pointcut, BeanMetadataElement> managers = new ManagedMap<>();
			List<Element> methods = DomUtils.getChildElementsByTagName(interceptMethodsElt, Elements.PROTECT);
			for (Element protectElt : methods) {
				managers.put(pointcut(interceptMethodsElt, protectElt),
						authorizationManager(interceptMethodsElt, protectElt));
			}
			return interceptor.addConstructorArgValue(Pointcut.TRUE)
					.addConstructorArgValue(authorizationManager(managers)).getBeanDefinition();
		}

		boolean supports(Node node) {
			Element interceptMethodsElt = (Element) node;
			if (Boolean.parseBoolean(interceptMethodsElt.getAttribute(ATT_USE_AUTHORIZATION_MGR))) {
				return true;
			}
			return StringUtils.hasText(interceptMethodsElt.getAttribute(ATT_AUTHORIZATION_MGR));
		}

		private Pointcut pointcut(Element interceptorElt, Element protectElt) {
			String method = protectElt.getAttribute(ATT_METHOD);
			Class<?> javaType = javaType(interceptorElt, method);
			return new PrefixBasedMethodMatcher(javaType, method);
		}

		private BeanMetadataElement authorizationManager(Element interceptMethodsElt, Element protectElt) {
			String authorizationManager = interceptMethodsElt.getAttribute(ATT_AUTHORIZATION_MGR);
			if (StringUtils.hasText(authorizationManager)) {
				return new RuntimeBeanReference(authorizationManager);
			}
			String access = protectElt.getAttribute(ATT_ACCESS);
			SpelExpressionParser parser = new SpelExpressionParser();
			Expression expression = parser.parseExpression(access);
			return BeanDefinitionBuilder.rootBeanDefinition(MethodExpressionAuthorizationManager.class)
					.addConstructorArgValue(expression).getBeanDefinition();
		}

		private BeanMetadataElement authorizationManager(Map<Pointcut, BeanMetadataElement> managers) {
			return BeanDefinitionBuilder.rootBeanDefinition(PointcutMatchingAuthorizationManager.class)
					.addConstructorArgValue(managers).getBeanDefinition();
		}

		private Class<?> javaType(Element interceptMethodsElt, String method) {
			int lastDotIndex = method.lastIndexOf(".");
			String parentBeanClass = ((Element) interceptMethodsElt.getParentNode()).getAttribute("class");
			Assert.isTrue(lastDotIndex != -1 || StringUtils.hasText(parentBeanClass),
					() -> "'" + method + "' is not a valid method name: format is FQN.methodName");
			if (lastDotIndex == -1) {
				return ClassUtils.resolveClassName(parentBeanClass, this.beanClassLoader);
			}
			String methodName = method.substring(lastDotIndex + 1);
			Assert.hasText(methodName, () -> "Method not found for '" + method + "'");
			String typeName = method.substring(0, lastDotIndex);
			return ClassUtils.resolveClassName(typeName, this.beanClassLoader);
		}

		private static class PrefixBasedMethodMatcher implements MethodMatcher, Pointcut {

			private final ClassFilter classFilter;

			private final String methodPrefix;

			PrefixBasedMethodMatcher(Class<?> javaType, String methodPrefix) {
				this.classFilter = new RootClassFilter(javaType);
				this.methodPrefix = methodPrefix;
			}

			@Override
			public ClassFilter getClassFilter() {
				return this.classFilter;
			}

			@Override
			public MethodMatcher getMethodMatcher() {
				return this;
			}

			@Override
			public boolean matches(Method method, Class<?> targetClass) {
				return matches(this.methodPrefix, method.getName());
			}

			@Override
			public boolean isRuntime() {
				return false;
			}

			@Override
			public boolean matches(Method method, Class<?> targetClass, Object... args) {
				return matches(this.methodPrefix, method.getName());
			}

			private boolean matches(String mappedName, String methodName) {
				boolean equals = methodName.equals(mappedName);
				return equals || prefixMatches(mappedName, methodName) || suffixMatches(mappedName, methodName);
			}

			private boolean prefixMatches(String mappedName, String methodName) {
				return mappedName.endsWith("*")
						&& methodName.startsWith(mappedName.substring(0, mappedName.length() - 1));
			}

			private boolean suffixMatches(String mappedName, String methodName) {
				return mappedName.startsWith("*") && methodName.endsWith(mappedName.substring(1));
			}

		}

		private static class PointcutMatchingAuthorizationManager implements AuthorizationManager<MethodInvocation> {

			private final Map<Pointcut, AuthorizationManager<MethodInvocation>> managers;

			PointcutMatchingAuthorizationManager(Map<Pointcut, AuthorizationManager<MethodInvocation>> managers) {
				this.managers = managers;
			}

			@Override
			public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocation object) {
				for (Map.Entry<Pointcut, AuthorizationManager<MethodInvocation>> entry : this.managers.entrySet()) {
					Class<?> targetClass = (object.getThis() != null) ? AopUtils.getTargetClass(object.getThis())
							: null;
					if (entry.getKey().getClassFilter().matches(targetClass)
							&& entry.getKey().getMethodMatcher().matches(object.getMethod(), targetClass)) {
						return entry.getValue().check(authentication, object);
					}
				}
				return new AuthorizationDecision(false);
			}

		}

		private static class MethodExpressionAuthorizationManager implements AuthorizationManager<MethodInvocation> {

			private final Expression expression;

			private SecurityExpressionHandler<MethodInvocation> expressionHandler = new DefaultMethodSecurityExpressionHandler();

			MethodExpressionAuthorizationManager(Expression expression) {
				this.expression = expression;
			}

			@Override
			public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocation invocation) {
				EvaluationContext ctx = this.expressionHandler.createEvaluationContext(authentication, invocation);
				boolean granted = ExpressionUtils.evaluateAsBoolean(this.expression, ctx);
				return new ExpressionAuthorizationDecision(granted, this.expression);
			}

			void setExpressionHandler(SecurityExpressionHandler<MethodInvocation> expressionHandler) {
				this.expressionHandler = expressionHandler;
			}

		}

	}

	/**
	 * This is the real class which does the work. We need access to the ParserContext in
	 * order to do bean registration.
	 */
	static class InternalInterceptMethodsBeanDefinitionDecorator
			extends AbstractInterceptorDrivenBeanDefinitionDecorator {

		static final String ATT_METHOD = "method";

		static final String ATT_ACCESS = "access";

		private static final String ATT_ACCESS_MGR = "access-decision-manager-ref";

		@Override
		protected BeanDefinition createInterceptorDefinition(Node node) {
			Element interceptMethodsElt = (Element) node;
			BeanDefinitionBuilder interceptor = BeanDefinitionBuilder
					.rootBeanDefinition(MethodSecurityInterceptor.class);
			// Default to autowiring to pick up after invocation mgr
			interceptor.setAutowireMode(AbstractBeanDefinition.AUTOWIRE_BY_TYPE);
			String accessManagerId = interceptMethodsElt.getAttribute(ATT_ACCESS_MGR);
			if (!StringUtils.hasText(accessManagerId)) {
				accessManagerId = BeanIds.METHOD_ACCESS_MANAGER;
			}
			interceptor.addPropertyValue("accessDecisionManager", new RuntimeBeanReference(accessManagerId));
			interceptor.addPropertyValue("authenticationManager",
					new RuntimeBeanReference(BeanIds.AUTHENTICATION_MANAGER));
			// Lookup parent bean information
			String parentBeanClass = ((Element) interceptMethodsElt.getParentNode()).getAttribute("class");
			// Parse the included methods
			List<Element> methods = DomUtils.getChildElementsByTagName(interceptMethodsElt, Elements.PROTECT);
			Map<String, BeanDefinition> mappings = new ManagedMap<>();
			for (Element protectmethodElt : methods) {
				BeanDefinitionBuilder attributeBuilder = BeanDefinitionBuilder.rootBeanDefinition(SecurityConfig.class);
				attributeBuilder.setFactoryMethod("createListFromCommaDelimitedString");
				attributeBuilder.addConstructorArgValue(protectmethodElt.getAttribute(ATT_ACCESS));
				// Support inference of class names
				String methodName = protectmethodElt.getAttribute(ATT_METHOD);
				if (methodName.lastIndexOf(".") == -1) {
					if (parentBeanClass != null && !"".equals(parentBeanClass)) {
						methodName = parentBeanClass + "." + methodName;
					}
				}
				mappings.put(methodName, attributeBuilder.getBeanDefinition());
			}
			BeanDefinition metadataSource = new RootBeanDefinition(MapBasedMethodSecurityMetadataSource.class);
			metadataSource.getConstructorArgumentValues().addGenericArgumentValue(mappings);
			interceptor.addPropertyValue("securityMetadataSource", metadataSource);
			return interceptor.getBeanDefinition();
		}

	}

}
