package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.ui.logout.LogoutFilter;
import org.springframework.security.ui.logout.SecurityContextLogoutHandler;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @author Ben Alex
 * @version $Id$
 */
public class LogoutBeanDefinitionParser implements BeanDefinitionParser {
    static final String ATT_LOGOUT_SUCCESS_URL = "logout-success-url";
	static final String DEF_LOGOUT_SUCCESS_URL = "/";

	static final String ATT_INVALIDATE_SESSION = "invalidate-session";
	static final String DEF_INVALIDATE_SESSION  = "true";

	static final String ATT_LOGOUT_URL = "logout-url";
	static final String DEF_LOGOUT_URL = "/j_spring_security_logout";

	public BeanDefinition parse(Element element, ParserContext parserContext) {
		String logoutUrl = null;
        String logoutSuccessUrl = null;
        String invalidateSession = null;

        if (element != null) {
            logoutUrl = element.getAttribute(ATT_LOGOUT_URL);
            logoutSuccessUrl = element.getAttribute(ATT_LOGOUT_SUCCESS_URL);
            invalidateSession = element.getAttribute(ATT_INVALIDATE_SESSION);
        }

        BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(LogoutFilter.class);
        builder.setSource(parserContext.extractSource(element));

        if (!StringUtils.hasText(logoutUrl)) {
        	logoutUrl = DEF_LOGOUT_URL;
        }
        builder.addPropertyValue("filterProcessesUrl", logoutUrl);

        if (!StringUtils.hasText(logoutSuccessUrl)) {
            logoutSuccessUrl = DEF_LOGOUT_SUCCESS_URL;
        }
        builder.addConstructorArg(logoutSuccessUrl);

        if (!StringUtils.hasText(invalidateSession)) {
        	invalidateSession = DEF_INVALIDATE_SESSION;
        }

        ManagedList handlers = new ManagedList();
        SecurityContextLogoutHandler sclh = new SecurityContextLogoutHandler();
        if ("true".equals(invalidateSession)) {
        	sclh.setInvalidateHttpSession(true);
        } else {
        	sclh.setInvalidateHttpSession(false);
        }
        handlers.add(sclh);

        if (parserContext.getRegistry().containsBeanDefinition(BeanIds.REMEMBER_ME_SERVICES)) {
            handlers.add(new RuntimeBeanReference(BeanIds.REMEMBER_ME_SERVICES));
        }

        builder.addConstructorArg(handlers);

        parserContext.getRegistry().registerBeanDefinition(BeanIds.LOGOUT_FILTER, builder.getBeanDefinition());
        ConfigUtils.addHttpFilter(parserContext, new RuntimeBeanReference(BeanIds.LOGOUT_FILTER));
        
        return null;
	}
}
