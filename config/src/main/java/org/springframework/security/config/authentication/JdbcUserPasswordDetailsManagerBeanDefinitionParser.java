/*
 * Copyright 2002-2023 the original author or authors.
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

import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.Elements;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @author Geir Hedemark
 */
public final class JdbcUserPasswordDetailsManagerBeanDefinitionParser extends AbstractUserDetailsServiceBeanDefinitionParser {
	static final String ATT_DATA_SOURCE = "data-source-ref";
	static final String ATT_USERS_BY_USERNAME_QUERY = "users-by-username-query";
	static final String ATT_AUTHORITIES_BY_USERNAME_QUERY = "authorities-by-username-query";
	static final String ATT_GROUP_AUTHORITIES_QUERY = "group-authorities-by-username-query";
	static final String ATT_CHANGE_PASSWORD_QUERY = "change-password-query";
	static final String ATT_ROLE_PREFIX = "role-prefix";

	@Override
	protected String getBeanClassName(Element element) {
		return "org.springframework.security.provisioning.JdbcUserPasswordDetailsManager";
	}

	@Override
	protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
		String dataSource = element.getAttribute(ATT_DATA_SOURCE);
		if (dataSource != null) {
			builder.addPropertyReference("dataSource", dataSource);
		}
		else {
			parserContext.getReaderContext()
					.error(ATT_DATA_SOURCE + " is required for " + Elements.JDBC_USER_PASSWORD_SERVICE,
							parserContext.extractSource(element));
		}
		String usersQuery = element.getAttribute(ATT_USERS_BY_USERNAME_QUERY);
		String authoritiesQuery = element.getAttribute(ATT_AUTHORITIES_BY_USERNAME_QUERY);
		String groupAuthoritiesQuery = element.getAttribute(ATT_GROUP_AUTHORITIES_QUERY);
		String changePasswordQuery = element.getAttribute(ATT_CHANGE_PASSWORD_QUERY);
		String rolePrefix = element.getAttribute(ATT_ROLE_PREFIX);
		if (StringUtils.hasText(rolePrefix)) {
			builder.addPropertyValue("rolePrefix", rolePrefix);
		}
		if (StringUtils.hasText(usersQuery)) {
			builder.addPropertyValue("usersByUsernameQuery", usersQuery);
		}
		if (StringUtils.hasText(authoritiesQuery)) {
			builder.addPropertyValue("authoritiesByUsernameQuery", authoritiesQuery);
		}
		if (StringUtils.hasText(groupAuthoritiesQuery)) {
			builder.addPropertyValue("enableGroups", Boolean.TRUE);
			builder.addPropertyValue("groupAuthoritiesByUsernameQuery", groupAuthoritiesQuery);
		}
		if (StringUtils.hasText(changePasswordQuery)) {
			builder.addPropertyValue("changePasswordQuery", changePasswordQuery);
		}
	}

}
