package org.springframework.security.config;

import org.springframework.security.ui.logout.LogoutFilter;
import org.springframework.security.ui.logout.SecurityContextLogoutHandler;
import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.StringUtils;

import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @author Ben Alex
 * @version $Id$
 */
public class LogoutBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {
    static final String ATT_LOGOUT_SUCCESS_URL = "logoutSuccessUrl";
	static final String ATT_LOGOUT_URL = "logoutUrl";
	public static final String DEF_LOGOUT_SUCCESS_URL = "/";

    protected Class getBeanClass(Element element) {
        return LogoutFilter.class;
    }

    protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
        String logoutUrl = element.getAttribute(ATT_LOGOUT_URL);

        if (StringUtils.hasText(logoutUrl)) {
            builder.addPropertyValue("filterProcessesUrl", logoutUrl);
        }

        String logoutSuccessUrl = element.getAttribute(ATT_LOGOUT_SUCCESS_URL);

        if (!StringUtils.hasText(logoutSuccessUrl)) {
            logoutSuccessUrl = DEF_LOGOUT_SUCCESS_URL;
        }

        builder.addConstructorArg(logoutSuccessUrl);
        ManagedList handlers = new ManagedList();
        handlers.add(new SecurityContextLogoutHandler());

        if (parserContext.getRegistry().containsBeanDefinition(BeanIds.REMEMBER_ME_SERVICES)) {
            handlers.add(new RuntimeBeanReference(BeanIds.REMEMBER_ME_SERVICES));
        }

        builder.addConstructorArg(handlers);

    }

    protected String resolveId(Element element, AbstractBeanDefinition definition, ParserContext parserContext) throws BeanDefinitionStoreException {
        String id = super.resolveId(element, definition, parserContext);

        if (StringUtils.hasText(id)) {
            return id;
        }

        return BeanIds.LOGOUT_FILTER;
    }
}
