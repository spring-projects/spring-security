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

package org.springframework.security.config.http;

import org.w3c.dom.Element;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.CorsFilter;

/**
 * Parser for the {@code CorsFilter}.
 *
 * @author Rob Winch
 * @since 4.1.1
 */
public class CorsBeanDefinitionParser {

	private static final String HANDLER_MAPPING_INTROSPECTOR = "org.springframework.web.servlet.handler.HandlerMappingIntrospector";

	private static final String ATT_SOURCE = "configuration-source-ref";

	private static final String ATT_REF = "ref";

	public BeanMetadataElement parse(Element element, ParserContext parserContext) {
		if (element == null) {
			return null;
		}
		String filterRef = element.getAttribute(ATT_REF);
		if (StringUtils.hasText(filterRef)) {
			return new RuntimeBeanReference(filterRef);
		}
		BeanMetadataElement configurationSource = getSource(element, parserContext);
		if (configurationSource == null) {
			throw new BeanCreationException("Could not create CorsFilter");
		}
		BeanDefinitionBuilder filterBldr = BeanDefinitionBuilder.rootBeanDefinition(CorsFilter.class);
		filterBldr.addConstructorArgValue(configurationSource);
		return filterBldr.getBeanDefinition();
	}

	public BeanMetadataElement getSource(Element element, ParserContext parserContext) {
		String configurationSourceRef = element.getAttribute(ATT_SOURCE);
		if (StringUtils.hasText(configurationSourceRef)) {
			return new RuntimeBeanReference(configurationSourceRef);
		}
		boolean mvcPresent = ClassUtils.isPresent(HANDLER_MAPPING_INTROSPECTOR, getClass().getClassLoader());
		if (!mvcPresent) {
			return null;
		}
		return new RootBeanDefinition(HandlerMappingIntrospectorFactoryBean.class);
	}

}
