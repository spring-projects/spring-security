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
package org.springframework.security.config.ldap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.Elements;
import org.springframework.security.config.authentication.PasswordEncoderParser;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Ldap authentication provider namespace configuration.
 *
 * @author Luke Taylor
 * @since 2.0
 */
public class LdapProviderBeanDefinitionParser implements BeanDefinitionParser {
	private final Log logger = LogFactory.getLog(getClass());

	private static final String ATT_USER_DN_PATTERN = "user-dn-pattern";
	private static final String ATT_USER_PASSWORD = "password-attribute";
	private static final String ATT_HASH = PasswordEncoderParser.ATT_HASH;

	private static final String DEF_USER_SEARCH_FILTER = "uid={0}";

	static final String PROVIDER_CLASS = "org.springframework.security.ldap.authentication.LdapAuthenticationProvider";
	static final String BIND_AUTH_CLASS = "org.springframework.security.ldap.authentication.BindAuthenticator";
	static final String PASSWD_AUTH_CLASS = "org.springframework.security.ldap.authentication.PasswordComparisonAuthenticator";

	public BeanDefinition parse(Element elt, ParserContext parserContext) {
		RuntimeBeanReference contextSource = LdapUserServiceBeanDefinitionParser
				.parseServerReference(elt, parserContext);

		BeanDefinition searchBean = LdapUserServiceBeanDefinitionParser.parseSearchBean(
				elt, parserContext);
		String userDnPattern = elt.getAttribute(ATT_USER_DN_PATTERN);

		String[] userDnPatternArray = new String[0];

		if (StringUtils.hasText(userDnPattern)) {
			userDnPatternArray = new String[] { userDnPattern };
			// TODO: Validate the pattern and make sure it is a valid DN.
		}
		else if (searchBean == null) {
			logger.info("No search information or DN pattern specified. Using default search filter '"
					+ DEF_USER_SEARCH_FILTER + "'");
			BeanDefinitionBuilder searchBeanBuilder = BeanDefinitionBuilder
					.rootBeanDefinition(LdapUserServiceBeanDefinitionParser.LDAP_SEARCH_CLASS);
			searchBeanBuilder.getRawBeanDefinition().setSource(elt);
			searchBeanBuilder.addConstructorArgValue("");
			searchBeanBuilder.addConstructorArgValue(DEF_USER_SEARCH_FILTER);
			searchBeanBuilder.addConstructorArgValue(contextSource);
			searchBean = searchBeanBuilder.getBeanDefinition();
		}

		BeanDefinitionBuilder authenticatorBuilder = BeanDefinitionBuilder
				.rootBeanDefinition(BIND_AUTH_CLASS);
		Element passwordCompareElt = DomUtils.getChildElementByTagName(elt,
				Elements.LDAP_PASSWORD_COMPARE);

		if (passwordCompareElt != null) {
			authenticatorBuilder = BeanDefinitionBuilder
					.rootBeanDefinition(PASSWD_AUTH_CLASS);

			String passwordAttribute = passwordCompareElt.getAttribute(ATT_USER_PASSWORD);
			if (StringUtils.hasText(passwordAttribute)) {
				authenticatorBuilder.addPropertyValue("passwordAttributeName",
						passwordAttribute);
			}

			Element passwordEncoderElement = DomUtils.getChildElementByTagName(
					passwordCompareElt, Elements.PASSWORD_ENCODER);
			String hash = passwordCompareElt.getAttribute(ATT_HASH);

			if (passwordEncoderElement != null) {
				if (StringUtils.hasText(hash)) {
					parserContext.getReaderContext().warning(
							"Attribute 'hash' cannot be used with 'password-encoder' and "
									+ "will be ignored.",
							parserContext.extractSource(elt));
				}
				PasswordEncoderParser pep = new PasswordEncoderParser(
						passwordEncoderElement, parserContext);
				authenticatorBuilder.addPropertyValue("passwordEncoder",
						pep.getPasswordEncoder());
			}
			else if (StringUtils.hasText(hash)) {
				authenticatorBuilder.addPropertyValue("passwordEncoder",
						PasswordEncoderParser.createPasswordEncoderBeanDefinition(hash,
								false));
			}
		}

		authenticatorBuilder.addConstructorArgValue(contextSource);
		authenticatorBuilder.addPropertyValue("userDnPatterns", userDnPatternArray);

		if (searchBean != null) {
			authenticatorBuilder.addPropertyValue("userSearch", searchBean);
		}

		BeanDefinitionBuilder ldapProvider = BeanDefinitionBuilder
				.rootBeanDefinition(PROVIDER_CLASS);
		ldapProvider.addConstructorArgValue(authenticatorBuilder.getBeanDefinition());
		ldapProvider.addConstructorArgValue(LdapUserServiceBeanDefinitionParser
				.parseAuthoritiesPopulator(elt, parserContext));
		ldapProvider.addPropertyValue("userDetailsContextMapper",
				LdapUserServiceBeanDefinitionParser.parseUserDetailsClassOrUserMapperRef(
						elt, parserContext));

		return ldapProvider.getBeanDefinition();
	}
}
