/*
 * Copyright 2002-2016 the original author or authors.
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

import java.util.List;
import java.util.Map;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.springframework.aop.config.AbstractInterceptorDrivenBeanDefinitionDecorator;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionDecorator;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.Elements;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;

/**
 * @author Luke Taylor
 * @author Ben Alex
 *
 */
public class InterceptMethodsBeanDefinitionDecorator implements BeanDefinitionDecorator {

	private final BeanDefinitionDecorator delegate = new InternalInterceptMethodsBeanDefinitionDecorator();

	@Override
	public BeanDefinitionHolder decorate(Node node, BeanDefinitionHolder definition, ParserContext parserContext) {
		MethodConfigUtils.registerDefaultMethodAccessManagerIfNecessary(parserContext);
		return this.delegate.decorate(node, definition, parserContext);
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
			String parentBeanClass = ((Element) node.getParentNode()).getAttribute("class");
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
