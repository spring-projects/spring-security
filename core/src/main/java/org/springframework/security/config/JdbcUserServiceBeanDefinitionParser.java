package org.springframework.security.config;

import org.springframework.security.userdetails.jdbc.JdbcUserDetailsManager;
import org.springframework.util.StringUtils;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;

import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class JdbcUserServiceBeanDefinitionParser extends AbstractUserDetailsServiceBeanDefinitionParser {
	static final String ATT_DATA_SOURCE = "data-source-ref";
	static final String ATT_USERS_BY_USERNAME_QUERY = "users-by-username-query";
	static final String ATT_AUTHORITIES_BY_USERNAME_QUERY = "authorities-by-username-query";
	static final String ATT_GROUP_AUTHORITIES_QUERY = "group-authorities-by-username-query";
	static final String ATT_ROLE_PREFIX = "role-prefix";

    protected Class getBeanClass(Element element) {
        return JdbcUserDetailsManager.class;
    }

    protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
        String dataSource = element.getAttribute(ATT_DATA_SOURCE);

        if (dataSource != null) {
            builder.addPropertyReference("dataSource", dataSource);
        } else {
            parserContext.getReaderContext().error(ATT_DATA_SOURCE  + " is required for "
                    + Elements.JDBC_USER_SERVICE, parserContext.extractSource(element));
        }
        
        String usersQuery = element.getAttribute(ATT_USERS_BY_USERNAME_QUERY);
        String authoritiesQuery = element.getAttribute(ATT_AUTHORITIES_BY_USERNAME_QUERY);
        String groupAuthoritiesQuery = element.getAttribute(ATT_GROUP_AUTHORITIES_QUERY);
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
            builder.addPropertyValue("authoritiesByUsernameQuery", groupAuthoritiesQuery);
        }
    }
}
