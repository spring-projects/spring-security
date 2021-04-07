/*
 * Copyright 2002-2018 the original author or authors.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import org.springframework.aop.config.AopNamespaceUtils;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.parsing.CompositeComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.authorization.method.Jsr250AuthorizationManager;
import org.springframework.security.authorization.method.PostAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PostFilterAuthorizationMethodInterceptor;
import org.springframework.security.authorization.method.PreAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PreFilterAuthorizationMethodInterceptor;
import org.springframework.security.config.Elements;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
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

	private static final String ATT_REF = "ref";

	@Override
	public BeanDefinition parse(Element element, ParserContext pc) {
		CompositeComponentDefinition compositeDef = new CompositeComponentDefinition(element.getTagName(),
				pc.extractSource(element));
		pc.pushContainingComponent(compositeDef);
		boolean prePostAnnotationsEnabled = !element.hasAttribute(ATT_USE_PREPOST)
				|| "true".equals(element.getAttribute(ATT_USE_PREPOST));
		if (prePostAnnotationsEnabled) {
			BeanDefinitionBuilder preFilterInterceptor = BeanDefinitionBuilder
					.rootBeanDefinition(PreFilterAuthorizationMethodInterceptor.class)
					.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
			BeanDefinitionBuilder preAuthorizeInterceptor = BeanDefinitionBuilder
					.rootBeanDefinition(PreAuthorizeAuthorizationMethodInterceptor.class)
					.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
			BeanDefinitionBuilder postAuthorizeInterceptor = BeanDefinitionBuilder
					.rootBeanDefinition(PostAuthorizeAuthorizationMethodInterceptor.class)
					.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
			BeanDefinitionBuilder postFilterInterceptor = BeanDefinitionBuilder
					.rootBeanDefinition(PostFilterAuthorizationMethodInterceptor.class)
					.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
			Element expressionHandlerElt = DomUtils.getChildElementByTagName(element, Elements.EXPRESSION_HANDLER);
			if (expressionHandlerElt != null) {
				String expressionHandlerRef = expressionHandlerElt.getAttribute(ATT_REF);
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
					.rootBeanDefinition(AuthorizationManagerBeforeMethodInterceptor.class)
					.setRole(BeanDefinition.ROLE_INFRASTRUCTURE).setFactoryMethod("secured");
			pc.getRegistry().registerBeanDefinition("securedAuthorizationMethodInterceptor",
					securedInterceptor.getBeanDefinition());
		}
		boolean jsr250Enabled = "true".equals(element.getAttribute(ATT_USE_JSR250));
		if (jsr250Enabled) {
			BeanDefinitionBuilder jsr250Interceptor = BeanDefinitionBuilder
					.rootBeanDefinition(Jsr250AuthorizationMethodInterceptor.class)
					.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
			pc.getRegistry().registerBeanDefinition("jsr250AuthorizationMethodInterceptor",
					jsr250Interceptor.getBeanDefinition());
		}
		AopNamespaceUtils.registerAutoProxyCreatorIfNecessary(pc, element);
		pc.popAndRegisterContainingComponent();
		return null;
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

		private final Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();

		@Override
		public AuthorizationManagerBeforeMethodInterceptor getObject() {
			return AuthorizationManagerBeforeMethodInterceptor.jsr250(this.manager);
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

	}

	public static final class PreAuthorizeAuthorizationMethodInterceptor
			implements FactoryBean<AuthorizationManagerBeforeMethodInterceptor> {

		private final PreAuthorizeAuthorizationManager manager = new PreAuthorizeAuthorizationManager();

		@Override
		public AuthorizationManagerBeforeMethodInterceptor getObject() {
			return AuthorizationManagerBeforeMethodInterceptor.preAuthorize(this.manager);
		}

		@Override
		public Class<?> getObjectType() {
			return AuthorizationManagerBeforeMethodInterceptor.class;
		}

		public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
			this.manager.setExpressionHandler(expressionHandler);
		}

	}

	public static final class PostAuthorizeAuthorizationMethodInterceptor
			implements FactoryBean<AuthorizationManagerAfterMethodInterceptor> {

		private final PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();

		@Override
		public AuthorizationManagerAfterMethodInterceptor getObject() {
			return AuthorizationManagerAfterMethodInterceptor.postAuthorize(this.manager);
		}

		@Override
		public Class<?> getObjectType() {
			return AuthorizationManagerAfterMethodInterceptor.class;
		}

		public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
			this.manager.setExpressionHandler(expressionHandler);
		}

	}

}
