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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.config.Elements;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 *
 * @author Luke Taylor
 * @since 3.1
 */
public class MethodSecurityMetadataSourceBeanDefinitionParser extends
		AbstractBeanDefinitionParser {
	static final String ATT_METHOD = "method";
	static final String ATT_ACCESS = "access";

	public AbstractBeanDefinition parseInternal(Element elt, ParserContext pc) {
		// Parse the included methods
		List<Element> methods = DomUtils.getChildElementsByTagName(elt, Elements.PROTECT);
		Map<String, List<ConfigAttribute>> mappings = new LinkedHashMap<>();

		for (Element protectmethodElt : methods) {
			String[] tokens = StringUtils
					.commaDelimitedListToStringArray(protectmethodElt
							.getAttribute(ATT_ACCESS));
			String methodName = protectmethodElt.getAttribute(ATT_METHOD);

			mappings.put(methodName, SecurityConfig.createList(tokens));
		}

		RootBeanDefinition metadataSource = new RootBeanDefinition(
				MapBasedMethodSecurityMetadataSource.class);
		metadataSource.getConstructorArgumentValues().addGenericArgumentValue(mappings);

		return metadataSource;
	}

}
