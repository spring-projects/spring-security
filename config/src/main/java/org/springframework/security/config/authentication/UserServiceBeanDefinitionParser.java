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
package org.springframework.security.config.authentication;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;

import org.w3c.dom.Element;

import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.PropertiesFactoryBean;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;

/**
 * @author Luke Taylor
 * @author Ben Alex
 */
public class UserServiceBeanDefinitionParser extends AbstractUserDetailsServiceBeanDefinitionParser {

	static final String ATT_PASSWORD = "password";
	static final String ATT_NAME = "name";
	static final String ELT_USER = "user";
	static final String ATT_AUTHORITIES = "authorities";
	static final String ATT_PROPERTIES = "properties";
	static final String ATT_DISABLED = "disabled";
	static final String ATT_LOCKED = "locked";

	private SecureRandom random;

	protected String getBeanClassName(Element element) {
		return InMemoryUserDetailsManager.class.getName();
	}

	@SuppressWarnings("unchecked")
	protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
		String userProperties = element.getAttribute(ATT_PROPERTIES);
		List<Element> userElts = DomUtils.getChildElementsByTagName(element, ELT_USER);

		if (StringUtils.hasText(userProperties)) {

			if (!CollectionUtils.isEmpty(userElts)) {
				throw new BeanDefinitionStoreException(
						"Use of a properties file and user elements are mutually exclusive");
			}

			BeanDefinition bd = new RootBeanDefinition(PropertiesFactoryBean.class);
			bd.getPropertyValues().addPropertyValue("location", userProperties);
			builder.addConstructorArgValue(bd);

			return;
		}

		if (CollectionUtils.isEmpty(userElts)) {
			throw new BeanDefinitionStoreException("You must supply user definitions, either with <" + ELT_USER
					+ "> child elements or a " + "properties file (using the '" + ATT_PROPERTIES + "' attribute)");
		}

		ManagedList<BeanDefinition> users = new ManagedList<>();

		for (Object elt : userElts) {
			Element userElt = (Element) elt;
			String userName = userElt.getAttribute(ATT_NAME);
			String password = userElt.getAttribute(ATT_PASSWORD);

			if (!StringUtils.hasLength(password)) {
				password = generateRandomPassword();
			}

			boolean locked = "true".equals(userElt.getAttribute(ATT_LOCKED));
			boolean disabled = "true".equals(userElt.getAttribute(ATT_DISABLED));
			BeanDefinitionBuilder authorities = BeanDefinitionBuilder.rootBeanDefinition(AuthorityUtils.class);
			authorities.addConstructorArgValue(userElt.getAttribute(ATT_AUTHORITIES));
			authorities.setFactoryMethod("commaSeparatedStringToAuthorityList");

			BeanDefinitionBuilder user = BeanDefinitionBuilder.rootBeanDefinition(User.class);
			user.addConstructorArgValue(userName);
			user.addConstructorArgValue(password);
			user.addConstructorArgValue(!disabled);
			user.addConstructorArgValue(true);
			user.addConstructorArgValue(true);
			user.addConstructorArgValue(!locked);
			user.addConstructorArgValue(authorities.getBeanDefinition());

			users.add(user.getBeanDefinition());
		}

		builder.addConstructorArgValue(users);
	}

	private String generateRandomPassword() {
		if (random == null) {
			try {
				random = SecureRandom.getInstance("SHA1PRNG");
			}
			catch (NoSuchAlgorithmException e) {
				// Shouldn't happen...
				throw new RuntimeException("Failed find SHA1PRNG algorithm!");
			}
		}
		return Long.toString(random.nextLong());
	}

}
