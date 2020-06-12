/*
 * Copyright 2002-2021 the original author or authors.
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

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.web.RequestMatcherRedirectFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

/**
 * The bean definition parser for a Well-Known URL for Changing Passwords.
 *
 * @author Evgeniy Cheban
 * @since 5.6
 */
public final class WellKnownChangePasswordBeanDefinitionParser implements BeanDefinitionParser {

	private static final String WELL_KNOWN_CHANGE_PASSWORD_PATTERN = "/.well-known/change-password";

	private static final String DEFAULT_CHANGE_PASSWORD_PAGE = "/change-password";

	private static final String ATT_CHANGE_PASSWORD_PAGE = "change-password-page";

	/**
	 * {@inheritDoc}
	 */
	@Override
	public BeanDefinition parse(Element element, ParserContext parserContext) {
		BeanDefinition changePasswordFilter = BeanDefinitionBuilder
				.rootBeanDefinition(RequestMatcherRedirectFilter.class)
				.addConstructorArgValue(new AntPathRequestMatcher(WELL_KNOWN_CHANGE_PASSWORD_PATTERN))
				.addConstructorArgValue(getChangePasswordPage(element)).getBeanDefinition();
		parserContext.getReaderContext().registerWithGeneratedName(changePasswordFilter);
		return changePasswordFilter;
	}

	private String getChangePasswordPage(Element element) {
		String changePasswordPage = element.getAttribute(ATT_CHANGE_PASSWORD_PAGE);
		return (StringUtils.hasText(changePasswordPage) ? changePasswordPage : DEFAULT_CHANGE_PASSWORD_PAGE);
	}

}
