package org.springframework.security.config.http;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @author Ben Alex
 */
class LogoutBeanDefinitionParser implements BeanDefinitionParser {
    static final String ATT_LOGOUT_SUCCESS_URL = "logout-success-url";
    static final String DEF_LOGOUT_SUCCESS_URL = "/";

    static final String ATT_INVALIDATE_SESSION = "invalidate-session";
    static final String DEF_INVALIDATE_SESSION  = "true";

    static final String ATT_LOGOUT_URL = "logout-url";
    static final String DEF_LOGOUT_URL = "/j_spring_security_logout";
    static final String ATT_LOGOUT_HANDLER = "success-handler-ref";

    final String rememberMeServices;

    public LogoutBeanDefinitionParser(String rememberMeServices) {
        this.rememberMeServices = rememberMeServices;
    }

    @SuppressWarnings("unchecked")
    public BeanDefinition parse(Element element, ParserContext pc) {
        String logoutUrl = null;
        String successHandlerRef = null;
        String logoutSuccessUrl = null;
        String invalidateSession = null;

        BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(LogoutFilter.class);

        if (element != null) {
            Object source = pc.extractSource(element);
            builder.getRawBeanDefinition().setSource(source);
            logoutUrl = element.getAttribute(ATT_LOGOUT_URL);
            successHandlerRef = element.getAttribute(ATT_LOGOUT_HANDLER);
            WebConfigUtils.validateHttpRedirect(logoutUrl, pc, source);
            logoutSuccessUrl = element.getAttribute(ATT_LOGOUT_SUCCESS_URL);
            WebConfigUtils.validateHttpRedirect(logoutSuccessUrl, pc, source);
            invalidateSession = element.getAttribute(ATT_INVALIDATE_SESSION);
        }

        if (!StringUtils.hasText(logoutUrl)) {
            logoutUrl = DEF_LOGOUT_URL;
        }
        builder.addPropertyValue("filterProcessesUrl", logoutUrl);

        if (StringUtils.hasText(successHandlerRef)) {
            if (StringUtils.hasText(logoutSuccessUrl)) {
                pc.getReaderContext().error("Use " + ATT_LOGOUT_URL + " or " + ATT_LOGOUT_HANDLER + ", but not both",
                        pc.extractSource(element));
            }
            builder.addConstructorArgReference(successHandlerRef);
        } else {
            // Use the logout URL if no handler set
            if (!StringUtils.hasText(logoutSuccessUrl)) {
                logoutSuccessUrl = DEF_LOGOUT_SUCCESS_URL;
            }
            builder.addConstructorArgValue(logoutSuccessUrl);
        }

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

        if (rememberMeServices != null) {
            handlers.add(new RuntimeBeanReference(rememberMeServices));
        }

        builder.addConstructorArgValue(handlers);

        return builder.getBeanDefinition();
    }
}
