/*
 * Copyright 2002-2015 the original author or authors.
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
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.parsing.CompositeComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.BeanIds;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.util.StringUtils;

/**
 * @author Luke Taylor
 * @author Ben Alex
 * @author Rob Winch
 * @author Oliver Becker
 */
class RememberMeBeanDefinitionParser implements BeanDefinitionParser {

	static final String ATT_DATA_SOURCE = "data-source-ref";
	static final String ATT_SERVICES_REF = "services-ref";
	static final String ATT_SERVICES_ALIAS = "services-alias";
	static final String ATT_TOKEN_REPOSITORY = "token-repository-ref";
	static final String ATT_USER_SERVICE_REF = "user-service-ref";
	static final String ATT_SUCCESS_HANDLER_REF = "authentication-success-handler-ref";
	static final String ATT_TOKEN_VALIDITY = "token-validity-seconds";
	static final String ATT_SECURE_COOKIE = "use-secure-cookie";
	static final String ATT_FORM_REMEMBERME_PARAMETER = "remember-me-parameter";
	static final String ATT_REMEMBERME_COOKIE = "remember-me-cookie";

	protected final Log logger = LogFactory.getLog(getClass());

	private final String key;

	private final BeanReference authenticationManager;

	private String rememberMeServicesId;

	RememberMeBeanDefinitionParser(String key, BeanReference authenticationManager) {
		this.key = key;
		this.authenticationManager = authenticationManager;
	}

	public BeanDefinition parse(Element element, ParserContext pc) {
		CompositeComponentDefinition compositeDef = new CompositeComponentDefinition(element.getTagName(),
				pc.extractSource(element));
		pc.pushContainingComponent(compositeDef);

		String tokenRepository = element.getAttribute(ATT_TOKEN_REPOSITORY);
		String dataSource = element.getAttribute(ATT_DATA_SOURCE);
		String userServiceRef = element.getAttribute(ATT_USER_SERVICE_REF);
		String successHandlerRef = element.getAttribute(ATT_SUCCESS_HANDLER_REF);
		String rememberMeServicesRef = element.getAttribute(ATT_SERVICES_REF);
		String tokenValiditySeconds = element.getAttribute(ATT_TOKEN_VALIDITY);
		String useSecureCookie = element.getAttribute(ATT_SECURE_COOKIE);
		String remembermeParameter = element.getAttribute(ATT_FORM_REMEMBERME_PARAMETER);
		String remembermeCookie = element.getAttribute(ATT_REMEMBERME_COOKIE);
		Object source = pc.extractSource(element);

		RootBeanDefinition services = null;

		boolean dataSourceSet = StringUtils.hasText(dataSource);
		boolean tokenRepoSet = StringUtils.hasText(tokenRepository);
		boolean servicesRefSet = StringUtils.hasText(rememberMeServicesRef);
		boolean userServiceSet = StringUtils.hasText(userServiceRef);
		boolean useSecureCookieSet = StringUtils.hasText(useSecureCookie);
		boolean tokenValiditySet = StringUtils.hasText(tokenValiditySeconds);
		boolean remembermeParameterSet = StringUtils.hasText(remembermeParameter);
		boolean remembermeCookieSet = StringUtils.hasText(remembermeCookie);

		if (servicesRefSet && (dataSourceSet || tokenRepoSet || userServiceSet || tokenValiditySet || useSecureCookieSet
				|| remembermeParameterSet || remembermeCookieSet)) {
			pc.getReaderContext()
					.error(ATT_SERVICES_REF + " can't be used in combination with attributes " + ATT_TOKEN_REPOSITORY
							+ "," + ATT_DATA_SOURCE + ", " + ATT_USER_SERVICE_REF + ", " + ATT_TOKEN_VALIDITY + ", "
							+ ATT_SECURE_COOKIE + ", " + ATT_FORM_REMEMBERME_PARAMETER + " or " + ATT_REMEMBERME_COOKIE,
							source);
		}

		if (dataSourceSet && tokenRepoSet) {
			pc.getReaderContext().error("Specify " + ATT_TOKEN_REPOSITORY + " or " + ATT_DATA_SOURCE + " but not both",
					source);
		}

		boolean isPersistent = dataSourceSet | tokenRepoSet;

		if (isPersistent) {
			Object tokenRepo;
			services = new RootBeanDefinition(PersistentTokenBasedRememberMeServices.class);

			if (tokenRepoSet) {
				tokenRepo = new RuntimeBeanReference(tokenRepository);
			}
			else {
				tokenRepo = new RootBeanDefinition(JdbcTokenRepositoryImpl.class);
				((BeanDefinition) tokenRepo).getPropertyValues().addPropertyValue("dataSource",
						new RuntimeBeanReference(dataSource));
			}
			services.getConstructorArgumentValues().addIndexedArgumentValue(2, tokenRepo);
		}
		else if (!servicesRefSet) {
			services = new RootBeanDefinition(TokenBasedRememberMeServices.class);
		}

		String servicesName;

		if (services != null) {
			RootBeanDefinition uds = new RootBeanDefinition();
			uds.setFactoryBeanName(BeanIds.USER_DETAILS_SERVICE_FACTORY);
			uds.setFactoryMethodName("cachingUserDetailsService");
			uds.getConstructorArgumentValues().addGenericArgumentValue(userServiceRef);

			services.getConstructorArgumentValues().addGenericArgumentValue(key);
			services.getConstructorArgumentValues().addGenericArgumentValue(uds);
			// tokenRepo is already added if it is a
			// PersistentTokenBasedRememberMeServices

			if (useSecureCookieSet) {
				services.getPropertyValues().addPropertyValue("useSecureCookie", Boolean.valueOf(useSecureCookie));
			}

			if (tokenValiditySet) {
				boolean isTokenValidityNegative = tokenValiditySeconds.startsWith("-");
				if (isTokenValidityNegative && isPersistent) {
					pc.getReaderContext().error(ATT_TOKEN_VALIDITY + " cannot be negative if using"
							+ " a persistent remember-me token repository", source);
				}
				services.getPropertyValues().addPropertyValue("tokenValiditySeconds", tokenValiditySeconds);
			}

			if (remembermeParameterSet) {
				services.getPropertyValues().addPropertyValue("parameter", remembermeParameter);
			}

			if (remembermeCookieSet) {
				services.getPropertyValues().addPropertyValue("cookieName", remembermeCookie);
			}

			services.setSource(source);
			servicesName = pc.getReaderContext().generateBeanName(services);
			pc.registerBeanComponent(new BeanComponentDefinition(services, servicesName));
		}
		else {
			servicesName = rememberMeServicesRef;
		}

		if (StringUtils.hasText(element.getAttribute(ATT_SERVICES_ALIAS))) {
			pc.getRegistry().registerAlias(servicesName, element.getAttribute(ATT_SERVICES_ALIAS));
		}

		this.rememberMeServicesId = servicesName;

		BeanDefinitionBuilder filter = BeanDefinitionBuilder.rootBeanDefinition(RememberMeAuthenticationFilter.class);
		filter.getRawBeanDefinition().setSource(source);

		if (StringUtils.hasText(successHandlerRef)) {
			filter.addPropertyReference("authenticationSuccessHandler", successHandlerRef);
		}

		filter.addConstructorArgValue(authenticationManager);
		filter.addConstructorArgReference(servicesName);

		pc.popAndRegisterContainingComponent();

		return filter.getBeanDefinition();
	}

	String getRememberMeServicesId() {
		return this.rememberMeServicesId;
	}

}
