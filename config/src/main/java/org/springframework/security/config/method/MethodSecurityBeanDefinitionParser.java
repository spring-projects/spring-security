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

import java.util.Collection;
import java.util.List;
import java.util.Map;

import io.micrometer.observation.ObservationRegistry;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import org.springframework.aop.Pointcut;
import org.springframework.aop.config.AopNamespaceUtils;
import org.springframework.aop.support.Pointcuts;
import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.CompositeComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.ObservationAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.authorization.method.Jsr250AuthorizationManager;
import org.springframework.security.authorization.method.MethodExpressionAuthorizationManager;
import org.springframework.security.authorization.method.MethodInvocationResult;
import org.springframework.security.authorization.method.PostAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PostFilterAuthorizationMethodInterceptor;
import org.springframework.security.authorization.method.PreAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PreFilterAuthorizationMethodInterceptor;
import org.springframework.security.authorization.method.SecuredAuthorizationManager;
import org.springframework.security.config.Elements;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;

/**
 * Processes the top-level "method-security" element.
 *
 * @author Josh Cummings
 * @since 5.6
 */
public class MethodSecurityBeanDefinitionParser implements BeanDefinitionParser {

	private final Log logger = LogFactory.getLog(getClass());

	private static final String ATT_USE_JSR250 = "jsr250-enabled";

	private static final String ATT_USE_SECURED = "secured-enabled";

	private static final String ATT_USE_PREPOST = "pre-post-enabled";

	private static final String ATT_AUTHORIZATION_MGR = "authorization-manager-ref";

	private static final String ATT_OBSERVATION_REGISTRY_REF = "observation-registry-ref";

	private static final String ATT_ACCESS = "access";

	private static final String ATT_EXPRESSION = "expression";

	private static final String ATT_MODE = "mode";

	private static final String ATT_SECURITY_CONTEXT_HOLDER_STRATEGY_REF = "security-context-holder-strategy-ref";

	@Override
	public BeanDefinition parse(Element element, ParserContext pc) {
		CompositeComponentDefinition compositeDef = new CompositeComponentDefinition(element.getTagName(),
				pc.extractSource(element));
		pc.pushContainingComponent(compositeDef);
		BeanMetadataElement securityContextHolderStrategy = getSecurityContextHolderStrategy(element);
		BeanMetadataElement observationRegistry = getObservationRegistry(element);
		boolean prePostAnnotationsEnabled = !element.hasAttribute(ATT_USE_PREPOST)
				|| "true".equals(element.getAttribute(ATT_USE_PREPOST));
		boolean useAspectJ = "aspectj".equals(element.getAttribute(ATT_MODE));
		if (prePostAnnotationsEnabled) {
			BeanDefinitionBuilder preFilterInterceptor = BeanDefinitionBuilder
					.rootBeanDefinition(PreFilterAuthorizationMethodInterceptor.class)
					.setRole(BeanDefinition.ROLE_INFRASTRUCTURE)
					.addPropertyValue("securityContextHolderStrategy", securityContextHolderStrategy);
			BeanDefinitionBuilder preAuthorizeInterceptor = BeanDefinitionBuilder
					.rootBeanDefinition(PreAuthorizeAuthorizationMethodInterceptor.class)
					.setRole(BeanDefinition.ROLE_INFRASTRUCTURE)
					.addPropertyValue("securityContextHolderStrategy", securityContextHolderStrategy)
					.addPropertyValue("observationRegistry", observationRegistry);
			BeanDefinitionBuilder postAuthorizeInterceptor = BeanDefinitionBuilder
					.rootBeanDefinition(PostAuthorizeAuthorizationMethodInterceptor.class)
					.setRole(BeanDefinition.ROLE_INFRASTRUCTURE)
					.addPropertyValue("securityContextHolderStrategy", securityContextHolderStrategy)
					.addPropertyValue("observationRegistry", observationRegistry);
			BeanDefinitionBuilder postFilterInterceptor = BeanDefinitionBuilder
					.rootBeanDefinition(PostFilterAuthorizationMethodInterceptor.class)
					.setRole(BeanDefinition.ROLE_INFRASTRUCTURE)
					.addPropertyValue("securityContextHolderStrategy", securityContextHolderStrategy);
			Element expressionHandlerElt = DomUtils.getChildElementByTagName(element, Elements.EXPRESSION_HANDLER);
			if (expressionHandlerElt != null) {
				String expressionHandlerRef = expressionHandlerElt.getAttribute("ref");
				preFilterInterceptor.addPropertyReference("expressionHandler", expressionHandlerRef);
				preAuthorizeInterceptor.addPropertyReference("expressionHandler", expressionHandlerRef);
				postAuthorizeInterceptor.addPropertyReference("expressionHandler", expressionHandlerRef);
				postFilterInterceptor.addPropertyReference("expressionHandler", expressionHandlerRef);
			}
			else {
				BeanDefinition expressionHandler = BeanDefinitionBuilder
						.rootBeanDefinition(MethodSecurityExpressionHandlerBean.class).getBeanDefinition();
				preFilterInterceptor.addPropertyValue("expressionHandler", expressionHandler);
				preAuthorizeInterceptor.addPropertyValue("expressionHandler", expressionHandler);
				postAuthorizeInterceptor.addPropertyValue("expressionHandler", expressionHandler);
				postFilterInterceptor.addPropertyValue("expressionHandler", expressionHandler);
			}
			pc.getRegistry().registerBeanDefinition("preFilterAuthorizationMethodInterceptor",
					preFilterInterceptor.getBeanDefinition());
			pc.getRegistry().registerBeanDefinition("preAuthorizeAuthorizationMethodInterceptor",
					preAuthorizeInterceptor.getBeanDefinition());
			pc.getRegistry().registerBeanDefinition("postAuthorizeAuthorizationMethodInterceptor",
					postAuthorizeInterceptor.getBeanDefinition());
			pc.getRegistry().registerBeanDefinition("postFilterAuthorizationMethodInterceptor",
					postFilterInterceptor.getBeanDefinition());
		}
		boolean securedEnabled = "true".equals(element.getAttribute(ATT_USE_SECURED));
		if (securedEnabled) {
			BeanDefinitionBuilder securedInterceptor = BeanDefinitionBuilder
					.rootBeanDefinition(SecuredAuthorizationMethodInterceptor.class)
					.setRole(BeanDefinition.ROLE_INFRASTRUCTURE)
					.addPropertyValue("securityContextHolderStrategy", securityContextHolderStrategy)
					.addPropertyValue("observationRegistry", observationRegistry);
			pc.getRegistry().registerBeanDefinition("securedAuthorizationMethodInterceptor",
					securedInterceptor.getBeanDefinition());
		}
		boolean jsr250Enabled = "true".equals(element.getAttribute(ATT_USE_JSR250));
		if (jsr250Enabled) {
			BeanDefinitionBuilder jsr250Interceptor = BeanDefinitionBuilder
					.rootBeanDefinition(Jsr250AuthorizationMethodInterceptor.class)
					.setRole(BeanDefinition.ROLE_INFRASTRUCTURE)
					.addPropertyValue("securityContextHolderStrategy", securityContextHolderStrategy)
					.addPropertyValue("observationRegistry", observationRegistry);
			pc.getRegistry().registerBeanDefinition("jsr250AuthorizationMethodInterceptor",
					jsr250Interceptor.getBeanDefinition());
		}
		Map<Pointcut, BeanMetadataElement> managers = new ManagedMap<>();
		List<Element> methods = DomUtils.getChildElementsByTagName(element, Elements.PROTECT_POINTCUT);
		if (useAspectJ) {
			if (!methods.isEmpty()) {
				pc.getReaderContext().error("Cannot use <protect-pointcut> and mode='aspectj' together",
						pc.extractSource(element));
			}
			registerInterceptors(pc.getRegistry());
		}
		else {
			if (!methods.isEmpty()) {
				for (Element protectElt : methods) {
					managers.put(pointcut(protectElt), authorizationManager(element, protectElt));
				}
				BeanDefinitionBuilder protectPointcutInterceptor = BeanDefinitionBuilder
						.rootBeanDefinition(AuthorizationManagerBeforeMethodInterceptor.class)
						.setRole(BeanDefinition.ROLE_INFRASTRUCTURE)
						.addPropertyValue("securityContextHolderStrategy", securityContextHolderStrategy)
						.addConstructorArgValue(pointcut(managers.keySet()))
						.addConstructorArgValue(authorizationManager(managers));
				pc.getRegistry().registerBeanDefinition("protectPointcutInterceptor",
						protectPointcutInterceptor.getBeanDefinition());
			}
			AopNamespaceUtils.registerAutoProxyCreatorIfNecessary(pc, element);
		}
		pc.popAndRegisterContainingComponent();
		return null;
	}

	private BeanMetadataElement getObservationRegistry(Element methodSecurityElmt) {
		String holderStrategyRef = methodSecurityElmt.getAttribute(ATT_OBSERVATION_REGISTRY_REF);
		if (StringUtils.hasText(holderStrategyRef)) {
			return new RuntimeBeanReference(holderStrategyRef);
		}
		return BeanDefinitionBuilder.rootBeanDefinition(ObservationRegistryFactory.class).getBeanDefinition();
	}

	private BeanMetadataElement getSecurityContextHolderStrategy(Element methodSecurityElmt) {
		String holderStrategyRef = methodSecurityElmt.getAttribute(ATT_SECURITY_CONTEXT_HOLDER_STRATEGY_REF);
		if (StringUtils.hasText(holderStrategyRef)) {
			return new RuntimeBeanReference(holderStrategyRef);
		}
		return BeanDefinitionBuilder.rootBeanDefinition(SecurityContextHolderStrategyFactory.class).getBeanDefinition();
	}

	private Pointcut pointcut(Element protectElt) {
		String expression = protectElt.getAttribute(ATT_EXPRESSION);
		expression = replaceBooleanOperators(expression);
		return new AspectJMethodMatcher(expression);
	}

	private Pointcut pointcut(Collection<Pointcut> pointcuts) {
		Pointcut result = null;
		for (Pointcut pointcut : pointcuts) {
			if (result == null) {
				result = pointcut;
			}
			else {
				result = Pointcuts.union(result, pointcut);
			}
		}
		return result;
	}

	private String replaceBooleanOperators(String expression) {
		expression = StringUtils.replace(expression, " and ", " && ");
		expression = StringUtils.replace(expression, " or ", " || ");
		expression = StringUtils.replace(expression, " not ", " ! ");
		return expression;
	}

	private BeanMetadataElement authorizationManager(Element element, Element protectElt) {
		String authorizationManager = element.getAttribute(ATT_AUTHORIZATION_MGR);
		if (StringUtils.hasText(authorizationManager)) {
			return new RuntimeBeanReference(authorizationManager);
		}
		String access = protectElt.getAttribute(ATT_ACCESS);
		return BeanDefinitionBuilder.rootBeanDefinition(MethodExpressionAuthorizationManager.class)
				.addConstructorArgValue(access).getBeanDefinition();
	}

	private BeanMetadataElement authorizationManager(Map<Pointcut, BeanMetadataElement> managers) {
		return BeanDefinitionBuilder.rootBeanDefinition(PointcutDelegatingAuthorizationManager.class)
				.addConstructorArgValue(managers).getBeanDefinition();
	}

	private void registerInterceptors(BeanDefinitionRegistry registry) {
		registerBeanDefinition("preFilterAuthorizationMethodInterceptor",
				"org.springframework.security.authorization.method.aspectj.PreFilterAspect", "preFilterAspect$0",
				registry);
		registerBeanDefinition("postFilterAuthorizationMethodInterceptor",
				"org.springframework.security.authorization.method.aspectj.PostFilterAspect", "postFilterAspect$0",
				registry);
		registerBeanDefinition("preAuthorizeAuthorizationMethodInterceptor",
				"org.springframework.security.authorization.method.aspectj.PreAuthorizeAspect", "preAuthorizeAspect$0",
				registry);
		registerBeanDefinition("postAuthorizeAuthorizationMethodInterceptor",
				"org.springframework.security.authorization.method.aspectj.PostAuthorizeAspect",
				"postAuthorizeAspect$0", registry);
		registerBeanDefinition("securedAuthorizationMethodInterceptor",
				"org.springframework.security.authorization.method.aspectj.SecuredAspect", "securedAspect$0", registry);
	}

	private void registerBeanDefinition(String beanName, String aspectClassName, String aspectBeanName,
			BeanDefinitionRegistry registry) {
		if (!registry.containsBeanDefinition(beanName)) {
			return;
		}
		BeanDefinition interceptor = registry.getBeanDefinition(beanName);
		BeanDefinitionBuilder aspect = BeanDefinitionBuilder.rootBeanDefinition(aspectClassName);
		aspect.setFactoryMethod("aspectOf");
		aspect.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
		aspect.addPropertyValue("securityInterceptor", interceptor);
		registry.registerBeanDefinition(aspectBeanName, aspect.getBeanDefinition());
	}

	public static final class MethodSecurityExpressionHandlerBean
			implements FactoryBean<MethodSecurityExpressionHandler>, ApplicationContextAware {

		private final DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();

		@Override
		public MethodSecurityExpressionHandler getObject() {
			return this.expressionHandler;
		}

		@Override
		public Class<?> getObjectType() {
			return MethodSecurityExpressionHandler.class;
		}

		@Override
		public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
			String[] grantedAuthorityDefaultsBeanNames = applicationContext
					.getBeanNamesForType(GrantedAuthorityDefaults.class);
			if (grantedAuthorityDefaultsBeanNames.length == 1) {
				GrantedAuthorityDefaults grantedAuthorityDefaults = applicationContext
						.getBean(grantedAuthorityDefaultsBeanNames[0], GrantedAuthorityDefaults.class);
				this.expressionHandler.setDefaultRolePrefix(grantedAuthorityDefaults.getRolePrefix());
			}
		}

	}

	public static final class Jsr250AuthorizationMethodInterceptor
			implements FactoryBean<AuthorizationManagerBeforeMethodInterceptor>, ApplicationContextAware {

		private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
				.getContextHolderStrategy();

		private ObservationRegistry observationRegistry = ObservationRegistry.NOOP;

		private final Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();

		@Override
		public AuthorizationManagerBeforeMethodInterceptor getObject() {
			AuthorizationManager<MethodInvocation> manager = this.manager;
			if (!this.observationRegistry.isNoop()) {
				manager = new ObservationAuthorizationManager<>(this.observationRegistry, this.manager);
			}
			AuthorizationManagerBeforeMethodInterceptor interceptor = AuthorizationManagerBeforeMethodInterceptor
					.jsr250(manager);
			interceptor.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
			return interceptor;
		}

		@Override
		public Class<?> getObjectType() {
			return AuthorizationManagerBeforeMethodInterceptor.class;
		}

		@Override
		public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
			String[] grantedAuthorityDefaultsBeanNames = applicationContext
					.getBeanNamesForType(GrantedAuthorityDefaults.class);
			if (grantedAuthorityDefaultsBeanNames.length == 1) {
				GrantedAuthorityDefaults grantedAuthorityDefaults = applicationContext
						.getBean(grantedAuthorityDefaultsBeanNames[0], GrantedAuthorityDefaults.class);
				this.manager.setRolePrefix(grantedAuthorityDefaults.getRolePrefix());
			}
		}

		public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
			this.securityContextHolderStrategy = securityContextHolderStrategy;
		}

		public void setObservationRegistry(ObservationRegistry observationRegistry) {
			this.observationRegistry = observationRegistry;
		}

	}

	public static final class SecuredAuthorizationMethodInterceptor
			implements FactoryBean<AuthorizationManagerBeforeMethodInterceptor> {

		private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
				.getContextHolderStrategy();

		private ObservationRegistry observationRegistry = ObservationRegistry.NOOP;

		private final SecuredAuthorizationManager manager = new SecuredAuthorizationManager();

		@Override
		public AuthorizationManagerBeforeMethodInterceptor getObject() {
			AuthorizationManager<MethodInvocation> manager = this.manager;
			if (!this.observationRegistry.isNoop()) {
				manager = new ObservationAuthorizationManager<>(this.observationRegistry, this.manager);
			}
			AuthorizationManagerBeforeMethodInterceptor interceptor = AuthorizationManagerBeforeMethodInterceptor
					.secured(manager);
			interceptor.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
			return interceptor;
		}

		@Override
		public Class<?> getObjectType() {
			return AuthorizationManagerBeforeMethodInterceptor.class;
		}

		public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
			this.securityContextHolderStrategy = securityContextHolderStrategy;
		}

		public void setObservationRegistry(ObservationRegistry observationRegistry) {
			this.observationRegistry = observationRegistry;
		}

	}

	public static final class PreAuthorizeAuthorizationMethodInterceptor
			implements FactoryBean<AuthorizationManagerBeforeMethodInterceptor> {

		private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
				.getContextHolderStrategy();

		private ObservationRegistry observationRegistry = ObservationRegistry.NOOP;

		private final PreAuthorizeAuthorizationManager manager = new PreAuthorizeAuthorizationManager();

		@Override
		public AuthorizationManagerBeforeMethodInterceptor getObject() {
			AuthorizationManager<MethodInvocation> manager = this.manager;
			if (!this.observationRegistry.isNoop()) {
				manager = new ObservationAuthorizationManager<>(this.observationRegistry, this.manager);
			}
			AuthorizationManagerBeforeMethodInterceptor interceptor = AuthorizationManagerBeforeMethodInterceptor
					.preAuthorize(manager);
			interceptor.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
			return interceptor;
		}

		@Override
		public Class<?> getObjectType() {
			return AuthorizationManagerBeforeMethodInterceptor.class;
		}

		public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
			this.securityContextHolderStrategy = securityContextHolderStrategy;
		}

		public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
			this.manager.setExpressionHandler(expressionHandler);
		}

		public void setObservationRegistry(ObservationRegistry registry) {
			this.observationRegistry = registry;
		}

	}

	public static final class PostAuthorizeAuthorizationMethodInterceptor
			implements FactoryBean<AuthorizationManagerAfterMethodInterceptor> {

		private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
				.getContextHolderStrategy();

		private ObservationRegistry observationRegistry = ObservationRegistry.NOOP;

		private final PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();

		@Override
		public AuthorizationManagerAfterMethodInterceptor getObject() {
			AuthorizationManager<MethodInvocationResult> manager = this.manager;
			if (!this.observationRegistry.isNoop()) {
				manager = new ObservationAuthorizationManager<>(this.observationRegistry, this.manager);
			}
			AuthorizationManagerAfterMethodInterceptor interceptor = AuthorizationManagerAfterMethodInterceptor
					.postAuthorize(manager);
			interceptor.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
			return interceptor;
		}

		@Override
		public Class<?> getObjectType() {
			return AuthorizationManagerAfterMethodInterceptor.class;
		}

		public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
			this.securityContextHolderStrategy = securityContextHolderStrategy;
		}

		public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
			this.manager.setExpressionHandler(expressionHandler);
		}

		public void setObservationRegistry(ObservationRegistry registry) {
			this.observationRegistry = registry;
		}

	}

	static class SecurityContextHolderStrategyFactory implements FactoryBean<SecurityContextHolderStrategy> {

		@Override
		public SecurityContextHolderStrategy getObject() throws Exception {
			return SecurityContextHolder.getContextHolderStrategy();
		}

		@Override
		public Class<?> getObjectType() {
			return SecurityContextHolderStrategy.class;
		}

	}

	static class ObservationRegistryFactory implements FactoryBean<ObservationRegistry> {

		@Override
		public ObservationRegistry getObject() throws Exception {
			return ObservationRegistry.NOOP;
		}

		@Override
		public Class<?> getObjectType() {
			return ObservationRegistry.class;
		}

	}

}
