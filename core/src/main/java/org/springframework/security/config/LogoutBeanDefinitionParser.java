package org.springframework.security.config;

import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.springframework.security.ui.logout.LogoutFilter;
import org.springframework.security.ui.logout.LogoutHandler;
import org.springframework.security.ui.logout.SecurityContextLogoutHandler;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class LogoutBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {
    public static final String DEFAULT_LOGOUT_SUCCESS_URL = "/";

    protected Class getBeanClass(Element element) {
        return LogoutFilter.class;
    }

    protected void doParse(Element element, BeanDefinitionBuilder builder) {
        String logoutUrl = element.getAttribute("logoutUrl");

        if (StringUtils.hasText(logoutUrl)) {
            builder.addPropertyValue("filterProcessesUrl", logoutUrl);
        }

        String logoutSuccessUrl = element.getAttribute("logoutSuccessUrl");

        if (!StringUtils.hasText(logoutSuccessUrl)) {
            logoutSuccessUrl = DEFAULT_LOGOUT_SUCCESS_URL;
        }

        builder.addConstructorArg(logoutSuccessUrl);
        builder.addConstructorArg(new LogoutHandler[] {new SecurityContextLogoutHandler()});
    }

    protected String resolveId(Element element, AbstractBeanDefinition definition, ParserContext parserContext) throws BeanDefinitionStoreException {
        String id = super.resolveId(element, definition, parserContext);

        if (StringUtils.hasText(id)) {
            return id;
        }

        return HttpSecurityBeanDefinitionParser.DEFAULT_LOGOUT_FILTER_ID;
    }
}
