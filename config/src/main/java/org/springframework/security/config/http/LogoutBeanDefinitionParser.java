/*
 * Copyright 2002-2012 the original author or authors.
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

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @author Ben Alex
 */
class LogoutBeanDefinitionParser implements BeanDefinitionParser {
	static final String ATT_LOGOUT_SUCCESS_URL = "logout-success-url";

	static final String ATT_INVALIDATE_SESSION = "invalidate-session";

	static final String ATT_LOGOUT_URL = "logout-url";
	static final String DEF_LOGOUT_URL = "/logout";
	static final String ATT_LOGOUT_HANDLER = "success-handler-ref";
	static final String ATT_DELETE_COOKIES = "delete-cookies";

	final String rememberMeServices;
	private final String defaultLogoutUrl;
	private ManagedList<BeanMetadataElement> logoutHandlers = new ManagedList<>();
	private boolean csrfEnabled;

	LogoutBeanDefinitionParser(String loginPageUrl, String rememberMeServices,
			BeanMetadataElement csrfLogoutHandler) {
		this.defaultLogoutUrl = loginPageUrl + "?logout";
		this.rememberMeServices = rememberMeServices;
		this.csrfEnabled = csrfLogoutHandler != null;
		if (this.csrfEnabled) {
			logoutHandlers.add(csrfLogoutHandler);
		}
	}

	public BeanDefinition parse(Element element, ParserContext pc) {
		String logoutUrl = null;
		String successHandlerRef = null;
		String logoutSuccessUrl = null;
		String invalidateSession = null;
		String deleteCookies = null;

		BeanDefinitionBuilder builder = BeanDefinitionBuilder
				.rootBeanDefinition(LogoutFilter.class);

		if (element != null) {
			Object source = pc.extractSource(element);
			builder.getRawBeanDefinition().setSource(source);
			logoutUrl = element.getAttribute(ATT_LOGOUT_URL);
			successHandlerRef = element.getAttribute(ATT_LOGOUT_HANDLER);
			WebConfigUtils.validateHttpRedirect(logoutUrl, pc, source);
			logoutSuccessUrl = element.getAttribute(ATT_LOGOUT_SUCCESS_URL);
			WebConfigUtils.validateHttpRedirect(logoutSuccessUrl, pc, source);
			invalidateSession = element.getAttribute(ATT_INVALIDATE_SESSION);
			deleteCookies = element.getAttribute(ATT_DELETE_COOKIES);
		}

		if (!StringUtils.hasText(logoutUrl)) {
			logoutUrl = DEF_LOGOUT_URL;
		}

		builder.addPropertyValue("logoutRequestMatcher",
				getLogoutRequestMatcher(logoutUrl));

		if (StringUtils.hasText(successHandlerRef)) {
			if (StringUtils.hasText(logoutSuccessUrl)) {
				pc.getReaderContext().error(
						"Use " + ATT_LOGOUT_SUCCESS_URL + " or " + ATT_LOGOUT_HANDLER
								+ ", but not both", pc.extractSource(element));
			}
			builder.addConstructorArgReference(successHandlerRef);
		}
		else {
			// Use the logout URL if no handler set
			if (!StringUtils.hasText(logoutSuccessUrl)) {
				logoutSuccessUrl = defaultLogoutUrl;
			}
			builder.addConstructorArgValue(logoutSuccessUrl);
		}

		BeanDefinition sclh = new RootBeanDefinition(SecurityContextLogoutHandler.class);
		sclh.getPropertyValues().addPropertyValue("invalidateHttpSession",
				!"false".equals(invalidateSession));
		logoutHandlers.add(sclh);

		if (rememberMeServices != null) {
			logoutHandlers.add(new RuntimeBeanReference(rememberMeServices));
		}

		if (StringUtils.hasText(deleteCookies)) {
			BeanDefinition cookieDeleter = new RootBeanDefinition(
					CookieClearingLogoutHandler.class);
			String[] names = StringUtils.tokenizeToStringArray(deleteCookies, ",");
			cookieDeleter.getConstructorArgumentValues().addGenericArgumentValue(names);
			logoutHandlers.add(cookieDeleter);
		}

		builder.addConstructorArgValue(logoutHandlers);

		return builder.getBeanDefinition();
	}

	private BeanDefinition getLogoutRequestMatcher(String logoutUrl) {
		BeanDefinitionBuilder matcherBuilder = BeanDefinitionBuilder
				.rootBeanDefinition("org.springframework.security.web.util.matcher.AntPathRequestMatcher");
		matcherBuilder.addConstructorArgValue(logoutUrl);
		if (this.csrfEnabled) {
			matcherBuilder.addConstructorArgValue("POST");
		}

		return matcherBuilder.getBeanDefinition();
	}

	ManagedList<BeanMetadataElement> getLogoutHandlers() {
		return logoutHandlers;
	}
}
