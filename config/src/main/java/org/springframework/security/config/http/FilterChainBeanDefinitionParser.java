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

import java.util.Collections;

import org.w3c.dom.Element;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * @author Luke Taylor
 */
public class FilterChainBeanDefinitionParser implements BeanDefinitionParser {

	private static final String ATT_REQUEST_MATCHER_REF = "request-matcher-ref";

	@Override
	public BeanDefinition parse(Element elt, ParserContext pc) {
		MatcherType matcherType = MatcherType.fromElement(elt);
		String path = elt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_PATH_PATTERN);
		String requestMatcher = elt.getAttribute(ATT_REQUEST_MATCHER_REF);
		String filters = elt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_FILTERS);

		BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(DefaultSecurityFilterChain.class);

		if (StringUtils.hasText(path)) {
			Assert.isTrue(!StringUtils.hasText(requestMatcher), "");
			builder.addConstructorArgValue(matcherType.createMatcher(pc, path, null));
		}
		else {
			Assert.isTrue(StringUtils.hasText(requestMatcher), "");
			builder.addConstructorArgReference(requestMatcher);
		}

		if (filters.equals(HttpSecurityBeanDefinitionParser.OPT_FILTERS_NONE)) {
			builder.addConstructorArgValue(Collections.EMPTY_LIST);
		}
		else {
			String[] filterBeanNames = StringUtils.tokenizeToStringArray(filters, ",");
			ManagedList<RuntimeBeanReference> filterChain = new ManagedList<>(filterBeanNames.length);

			for (String name : filterBeanNames) {
				filterChain.add(new RuntimeBeanReference(name));
			}

			builder.addConstructorArgValue(filterChain);
		}

		return builder.getBeanDefinition();
	}

}
