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

package org.springframework.security.config.authentication;

import org.w3c.dom.Element;

import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.authentication.CachingUserDetailsService;
import org.springframework.security.config.BeanIds;
import org.springframework.util.StringUtils;

/**
 * @author Luke Taylor
 */
public abstract class AbstractUserDetailsServiceBeanDefinitionParser implements BeanDefinitionParser {

	static final String CACHE_REF = "cache-ref";

	public static final String CACHING_SUFFIX = ".caching";

	protected abstract String getBeanClassName(Element element);

	protected abstract void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder);

	@Override
	public BeanDefinition parse(Element element, ParserContext parserContext) {
		BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(getBeanClassName(element));
		doParse(element, parserContext, builder);
		RootBeanDefinition userService = (RootBeanDefinition) builder.getBeanDefinition();
		String beanId = resolveId(element, userService, parserContext);
		parserContext.registerBeanComponent(new BeanComponentDefinition(userService, beanId));
		String cacheRef = element.getAttribute(CACHE_REF);
		// Register a caching version of the user service if there's a cache-ref
		if (StringUtils.hasText(cacheRef)) {
			BeanDefinitionBuilder cachingUSBuilder = BeanDefinitionBuilder
					.rootBeanDefinition(CachingUserDetailsService.class);
			cachingUSBuilder.addConstructorArgReference(beanId);
			cachingUSBuilder.addPropertyValue("userCache", new RuntimeBeanReference(cacheRef));
			BeanDefinition cachingUserService = cachingUSBuilder.getBeanDefinition();
			parserContext
					.registerBeanComponent(new BeanComponentDefinition(cachingUserService, beanId + CACHING_SUFFIX));
		}
		return null;
	}

	private String resolveId(Element element, AbstractBeanDefinition definition, ParserContext pc)
			throws BeanDefinitionStoreException {
		String id = element.getAttribute("id");
		if (pc.isNested()) {
			// We're inside an <authentication-provider> element
			if (!StringUtils.hasText(id)) {
				id = pc.getReaderContext().generateBeanName(definition);
			}
			BeanDefinition container = pc.getContainingBeanDefinition();
			container.getPropertyValues().add("userDetailsService", new RuntimeBeanReference(id));
		}
		if (StringUtils.hasText(id)) {
			return id;
		}
		// If top level, use the default name or throw an exception if already used
		if (pc.getRegistry().containsBeanDefinition(BeanIds.USER_DETAILS_SERVICE)) {
			throw new BeanDefinitionStoreException(
					"No id supplied and another bean is already registered as " + BeanIds.USER_DETAILS_SERVICE);
		}
		return BeanIds.USER_DETAILS_SERVICE;
	}

}
