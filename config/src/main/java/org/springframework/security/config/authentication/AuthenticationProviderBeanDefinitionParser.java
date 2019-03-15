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

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Elements;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Wraps a UserDetailsService bean with a DaoAuthenticationProvider and registers the
 * latter with the ProviderManager.
 *
 * @author Luke Taylor
 */
public class AuthenticationProviderBeanDefinitionParser implements BeanDefinitionParser {
	private static final String ATT_USER_DETAILS_REF = "user-service-ref";

	public BeanDefinition parse(Element element, ParserContext pc) {
		RootBeanDefinition authProvider = new RootBeanDefinition(DaoAuthenticationProvider.class);
		authProvider.setSource(pc.extractSource(element));

		Element passwordEncoderElt = DomUtils.getChildElementByTagName(element, Elements.PASSWORD_ENCODER);

		PasswordEncoderParser pep = new PasswordEncoderParser(passwordEncoderElt, pc);
		BeanMetadataElement passwordEncoder = pep.getPasswordEncoder();
		if (passwordEncoder != null) {
			authProvider.getPropertyValues()
				.addPropertyValue("passwordEncoder", passwordEncoder);
		}

		Element userServiceElt = DomUtils.getChildElementByTagName(element,
				Elements.USER_SERVICE);
		if (userServiceElt == null) {
			userServiceElt = DomUtils.getChildElementByTagName(element,
					Elements.JDBC_USER_SERVICE);
		}
		if (userServiceElt == null) {
			userServiceElt = DomUtils.getChildElementByTagName(element,
					Elements.LDAP_USER_SERVICE);
		}

		String ref = element.getAttribute(ATT_USER_DETAILS_REF);

		if (StringUtils.hasText(ref)) {
			if (userServiceElt != null) {
				pc.getReaderContext().error(
						"The " + ATT_USER_DETAILS_REF
								+ " attribute cannot be used in combination with child"
								+ "elements '" + Elements.USER_SERVICE + "', '"
								+ Elements.JDBC_USER_SERVICE + "' or '"
								+ Elements.LDAP_USER_SERVICE + "'", element);
			}

			authProvider.getPropertyValues().add("userDetailsService",
					new RuntimeBeanReference(ref));
		}
		else {
			// Use the child elements to create the UserDetailsService
			if (userServiceElt != null) {
				pc.getDelegate().parseCustomElement(userServiceElt, authProvider);
			}
			else {
				pc.getReaderContext().error("A user-service is required", element);
			}

			// Pinch the cache-ref from the UserDetailService element, if set.
			String cacheRef = userServiceElt
					.getAttribute(AbstractUserDetailsServiceBeanDefinitionParser.CACHE_REF);

			if (StringUtils.hasText(cacheRef)) {
				authProvider.getPropertyValues().addPropertyValue("userCache",
						new RuntimeBeanReference(cacheRef));
			}
		}

		return authProvider;
	}
}
