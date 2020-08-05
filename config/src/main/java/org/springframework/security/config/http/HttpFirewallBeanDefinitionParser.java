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

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.BeanIds;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * Injects the supplied {@code HttpFirewall} bean reference into the
 * {@code FilterChainProxy}.
 *
 * @author Luke Taylor
 */
public class HttpFirewallBeanDefinitionParser implements BeanDefinitionParser {

	public BeanDefinition parse(Element element, ParserContext pc) {
		String ref = element.getAttribute("ref");

		if (!StringUtils.hasText(ref)) {
			pc.getReaderContext().error("ref attribute is required", pc.extractSource(element));
		}

		// Ensure the FCP is registered.
		HttpSecurityBeanDefinitionParser.registerFilterChainProxyIfNecessary(pc, pc.extractSource(element));
		BeanDefinition filterChainProxy = pc.getRegistry().getBeanDefinition(BeanIds.FILTER_CHAIN_PROXY);
		filterChainProxy.getPropertyValues().addPropertyValue("firewall", new RuntimeBeanReference(ref));

		return null;
	}

}
