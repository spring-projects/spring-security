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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.web.authentication.ForwardAuthenticationFailureHandler;
import org.springframework.security.web.authentication.ForwardAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.util.StringUtils;

/**
 * @author Luke Taylor
 * @author Ben Alex
 * @author Rob Winch
 * @author Kazuki Shimizu
 * @author Shazin Sadakath
 */
public class FormLoginBeanDefinitionParser {

	protected final Log logger = LogFactory.getLog(getClass());

	private static final String ATT_LOGIN_URL = "login-processing-url";

	static final String ATT_LOGIN_PAGE = "login-page";

	private static final String DEF_LOGIN_PAGE = DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL;

	private static final String ATT_FORM_LOGIN_TARGET_URL = "default-target-url";

	private static final String ATT_ALWAYS_USE_DEFAULT_TARGET_URL = "always-use-default-target";

	private static final String DEF_FORM_LOGIN_TARGET_URL = "/";

	private static final String ATT_USERNAME_PARAMETER = "username-parameter";

	private static final String ATT_PASSWORD_PARAMETER = "password-parameter";

	private static final String ATT_FORM_LOGIN_AUTHENTICATION_FAILURE_URL = "authentication-failure-url";

	private static final String DEF_FORM_LOGIN_AUTHENTICATION_FAILURE_URL = DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL
			+ "?" + DefaultLoginPageGeneratingFilter.ERROR_PARAMETER_NAME;

	private static final String ATT_SUCCESS_HANDLER_REF = "authentication-success-handler-ref";

	private static final String ATT_FAILURE_HANDLER_REF = "authentication-failure-handler-ref";

	private static final String ATT_FORM_LOGIN_AUTHENTICATION_FAILURE_FORWARD_URL = "authentication-failure-forward-url";

	private static final String ATT_FORM_LOGIN_AUTHENTICATION_SUCCESS_FORWARD_URL = "authentication-success-forward-url";

	private final String defaultLoginProcessingUrl;

	private final String filterClassName;

	private final BeanReference requestCache;

	private final BeanReference sessionStrategy;

	private final boolean allowSessionCreation;

	private final BeanReference portMapper;

	private final BeanReference portResolver;

	private RootBeanDefinition filterBean;

	private RootBeanDefinition entryPointBean;

	private String loginPage;

	private String loginMethod;

	private String loginProcessingUrl;

	FormLoginBeanDefinitionParser(String defaultLoginProcessingUrl, String loginMethod, String filterClassName,
			BeanReference requestCache, BeanReference sessionStrategy, boolean allowSessionCreation,
			BeanReference portMapper, BeanReference portResolver) {
		this.defaultLoginProcessingUrl = defaultLoginProcessingUrl;
		this.loginMethod = loginMethod;
		this.filterClassName = filterClassName;
		this.requestCache = requestCache;
		this.sessionStrategy = sessionStrategy;
		this.allowSessionCreation = allowSessionCreation;
		this.portMapper = portMapper;
		this.portResolver = portResolver;
	}

	public BeanDefinition parse(Element elt, ParserContext pc) {
		String loginUrl = null;
		String defaultTargetUrl = null;
		String authenticationFailureUrl = null;
		String alwaysUseDefault = null;
		String successHandlerRef = null;
		String failureHandlerRef = null;
		// Only available with form-login
		String usernameParameter = null;
		String passwordParameter = null;
		String authDetailsSourceRef = null;
		String authenticationFailureForwardUrl = null;
		String authenticationSuccessForwardUrl = null;
		Object source = null;
		if (elt != null) {
			source = pc.extractSource(elt);
			loginUrl = elt.getAttribute(ATT_LOGIN_URL);
			WebConfigUtils.validateHttpRedirect(loginUrl, pc, source);
			defaultTargetUrl = elt.getAttribute(ATT_FORM_LOGIN_TARGET_URL);
			WebConfigUtils.validateHttpRedirect(defaultTargetUrl, pc, source);
			authenticationFailureUrl = elt.getAttribute(ATT_FORM_LOGIN_AUTHENTICATION_FAILURE_URL);
			WebConfigUtils.validateHttpRedirect(authenticationFailureUrl, pc, source);
			alwaysUseDefault = elt.getAttribute(ATT_ALWAYS_USE_DEFAULT_TARGET_URL);
			this.loginPage = elt.getAttribute(ATT_LOGIN_PAGE);
			successHandlerRef = elt.getAttribute(ATT_SUCCESS_HANDLER_REF);
			failureHandlerRef = elt.getAttribute(ATT_FAILURE_HANDLER_REF);
			authDetailsSourceRef = elt.getAttribute(AuthenticationConfigBuilder.ATT_AUTH_DETAILS_SOURCE_REF);
			authenticationFailureForwardUrl = elt.getAttribute(ATT_FORM_LOGIN_AUTHENTICATION_FAILURE_FORWARD_URL);
			WebConfigUtils.validateHttpRedirect(authenticationFailureForwardUrl, pc, source);
			authenticationSuccessForwardUrl = elt.getAttribute(ATT_FORM_LOGIN_AUTHENTICATION_SUCCESS_FORWARD_URL);
			WebConfigUtils.validateHttpRedirect(authenticationSuccessForwardUrl, pc, source);
			if (!StringUtils.hasText(this.loginPage)) {
				this.loginPage = null;
			}
			WebConfigUtils.validateHttpRedirect(this.loginPage, pc, source);
			usernameParameter = elt.getAttribute(ATT_USERNAME_PARAMETER);
			passwordParameter = elt.getAttribute(ATT_PASSWORD_PARAMETER);
		}
		this.filterBean = createFilterBean(loginUrl, defaultTargetUrl, alwaysUseDefault, this.loginPage,
				authenticationFailureUrl, successHandlerRef, failureHandlerRef, authDetailsSourceRef,
				authenticationFailureForwardUrl, authenticationSuccessForwardUrl);
		if (StringUtils.hasText(usernameParameter)) {
			this.filterBean.getPropertyValues().addPropertyValue("usernameParameter", usernameParameter);
		}
		if (StringUtils.hasText(passwordParameter)) {
			this.filterBean.getPropertyValues().addPropertyValue("passwordParameter", passwordParameter);
		}
		this.filterBean.setSource(source);
		BeanDefinitionBuilder entryPointBuilder = BeanDefinitionBuilder
				.rootBeanDefinition(LoginUrlAuthenticationEntryPoint.class);
		entryPointBuilder.getRawBeanDefinition().setSource(source);
		entryPointBuilder.addConstructorArgValue((this.loginPage != null) ? this.loginPage : DEF_LOGIN_PAGE);
		entryPointBuilder.addPropertyValue("portMapper", this.portMapper);
		entryPointBuilder.addPropertyValue("portResolver", this.portResolver);
		this.entryPointBean = (RootBeanDefinition) entryPointBuilder.getBeanDefinition();
		return null;
	}

	private RootBeanDefinition createFilterBean(String loginUrl, String defaultTargetUrl, String alwaysUseDefault,
			String loginPage, String authenticationFailureUrl, String successHandlerRef, String failureHandlerRef,
			String authDetailsSourceRef, String authenticationFailureForwardUrl,
			String authenticationSuccessForwardUrl) {
		BeanDefinitionBuilder filterBuilder = BeanDefinitionBuilder.rootBeanDefinition(this.filterClassName);
		if (!StringUtils.hasText(loginUrl)) {
			loginUrl = this.defaultLoginProcessingUrl;
		}
		this.loginProcessingUrl = loginUrl;
		BeanDefinitionBuilder matcherBuilder = BeanDefinitionBuilder
				.rootBeanDefinition("org.springframework.security.web.util.matcher.AntPathRequestMatcher");
		matcherBuilder.addConstructorArgValue(loginUrl);
		if (this.loginMethod != null) {
			matcherBuilder.addConstructorArgValue("POST");
		}
		filterBuilder.addPropertyValue("requiresAuthenticationRequestMatcher", matcherBuilder.getBeanDefinition());
		if (StringUtils.hasText(successHandlerRef)) {
			filterBuilder.addPropertyReference("authenticationSuccessHandler", successHandlerRef);
		}
		else if (StringUtils.hasText(authenticationSuccessForwardUrl)) {
			BeanDefinitionBuilder forwardSuccessHandler = BeanDefinitionBuilder
					.rootBeanDefinition(ForwardAuthenticationSuccessHandler.class);
			forwardSuccessHandler.addConstructorArgValue(authenticationSuccessForwardUrl);
			filterBuilder.addPropertyValue("authenticationSuccessHandler", forwardSuccessHandler.getBeanDefinition());
		}
		else {
			BeanDefinitionBuilder successHandler = BeanDefinitionBuilder
					.rootBeanDefinition(SavedRequestAwareAuthenticationSuccessHandler.class);
			if ("true".equals(alwaysUseDefault)) {
				successHandler.addPropertyValue("alwaysUseDefaultTargetUrl", Boolean.TRUE);
			}
			successHandler.addPropertyValue("requestCache", this.requestCache);
			successHandler.addPropertyValue("defaultTargetUrl",
					StringUtils.hasText(defaultTargetUrl) ? defaultTargetUrl : DEF_FORM_LOGIN_TARGET_URL);
			filterBuilder.addPropertyValue("authenticationSuccessHandler", successHandler.getBeanDefinition());
		}
		if (StringUtils.hasText(authDetailsSourceRef)) {
			filterBuilder.addPropertyReference("authenticationDetailsSource", authDetailsSourceRef);
		}
		if (this.sessionStrategy != null) {
			filterBuilder.addPropertyValue("sessionAuthenticationStrategy", this.sessionStrategy);
		}
		if (StringUtils.hasText(failureHandlerRef)) {
			filterBuilder.addPropertyReference("authenticationFailureHandler", failureHandlerRef);
		}
		else if (StringUtils.hasText(authenticationFailureForwardUrl)) {
			BeanDefinitionBuilder forwardFailureHandler = BeanDefinitionBuilder
					.rootBeanDefinition(ForwardAuthenticationFailureHandler.class);
			forwardFailureHandler.addConstructorArgValue(authenticationFailureForwardUrl);
			filterBuilder.addPropertyValue("authenticationFailureHandler", forwardFailureHandler.getBeanDefinition());
		}
		else {
			BeanDefinitionBuilder failureHandler = BeanDefinitionBuilder
					.rootBeanDefinition(SimpleUrlAuthenticationFailureHandler.class);
			if (!StringUtils.hasText(authenticationFailureUrl)) {
				// Fall back to re-displaying the custom login page, if one was specified.
				if (StringUtils.hasText(loginPage)) {
					authenticationFailureUrl = loginPage + "?" + DefaultLoginPageGeneratingFilter.ERROR_PARAMETER_NAME;
				}
				else {
					authenticationFailureUrl = DEF_FORM_LOGIN_AUTHENTICATION_FAILURE_URL;
				}
			}
			failureHandler.addPropertyValue("defaultFailureUrl", authenticationFailureUrl);
			failureHandler.addPropertyValue("allowSessionCreation", this.allowSessionCreation);
			filterBuilder.addPropertyValue("authenticationFailureHandler", failureHandler.getBeanDefinition());
		}
		return (RootBeanDefinition) filterBuilder.getBeanDefinition();
	}

	RootBeanDefinition getFilterBean() {
		return this.filterBean;
	}

	RootBeanDefinition getEntryPointBean() {
		return this.entryPointBean;
	}

	String getLoginPage() {
		return this.loginPage;
	}

	String getLoginProcessingUrl() {
		return this.loginProcessingUrl;
	}

}
