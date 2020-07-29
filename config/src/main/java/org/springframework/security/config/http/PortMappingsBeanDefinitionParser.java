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

package org.springframework.security.config.http;

import java.util.List;
import java.util.Map;

import org.w3c.dom.Element;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.Elements;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;

/**
 * Parses a port-mappings element, producing a single
 * {@link org.springframework.security.web.PortMapperImpl} bean.
 *
 * @author Luke Taylor
 */
class PortMappingsBeanDefinitionParser implements BeanDefinitionParser {

	public static final String ATT_HTTP_PORT = "http";

	public static final String ATT_HTTPS_PORT = "https";

	@Override
	@SuppressWarnings("unchecked")
	public BeanDefinition parse(Element element, ParserContext parserContext) {
		RootBeanDefinition portMapper = new RootBeanDefinition(PortMapperImpl.class);
		portMapper.setSource(parserContext.extractSource(element));

		if (element != null) {
			List<Element> mappingElts = DomUtils.getChildElementsByTagName(element, Elements.PORT_MAPPING);
			if (mappingElts.isEmpty()) {
				parserContext.getReaderContext().error("No port-mapping child elements specified", element);
			}

			Map mappings = new ManagedMap();

			for (Element elt : mappingElts) {
				String httpPort = elt.getAttribute(ATT_HTTP_PORT);
				String httpsPort = elt.getAttribute(ATT_HTTPS_PORT);

				if (!StringUtils.hasText(httpPort)) {
					parserContext.getReaderContext().error("No http port supplied in port mapping", elt);
				}

				if (!StringUtils.hasText(httpsPort)) {
					parserContext.getReaderContext().error("No https port supplied in port mapping", elt);
				}

				mappings.put(httpPort, httpsPort);
			}

			portMapper.getPropertyValues().addPropertyValue("portMappings", mappings);
		}

		return portMapper;
	}

}
