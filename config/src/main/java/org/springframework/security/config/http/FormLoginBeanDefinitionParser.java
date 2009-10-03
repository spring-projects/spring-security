package org.springframework.security.config.http;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @author Ben Alex
 * @version $Id$
 */
public class FormLoginBeanDefinitionParser {
    protected final Log logger = LogFactory.getLog(getClass());

    private static final String ATT_LOGIN_URL = "login-processing-url";

    static final String ATT_LOGIN_PAGE = "login-page";
    private static final String DEF_LOGIN_PAGE = DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL;

    private static final String ATT_FORM_LOGIN_TARGET_URL = "default-target-url";
    private static final String ATT_ALWAYS_USE_DEFAULT_TARGET_URL = "always-use-default-target";
    private static final String DEF_FORM_LOGIN_TARGET_URL = "/";

    private static final String ATT_FORM_LOGIN_AUTHENTICATION_FAILURE_URL = "authentication-failure-url";
    private static final String DEF_FORM_LOGIN_AUTHENTICATION_FAILURE_URL = DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL + "?" + DefaultLoginPageGeneratingFilter.ERROR_PARAMETER_NAME;

    private static final String ATT_SUCCESS_HANDLER_REF = "authentication-success-handler-ref";
    private static final String ATT_FAILURE_HANDLER_REF = "authentication-failure-handler-ref";

    private final String defaultLoginProcessingUrl;
    private final String filterClassName;
    private final BeanReference requestCache;
    private final BeanReference sessionStrategy;

    private RootBeanDefinition filterBean;
    private RootBeanDefinition entryPointBean;
    private String loginPage;

    FormLoginBeanDefinitionParser(String defaultLoginProcessingUrl, String filterClassName,
            BeanReference requestCache, BeanReference sessionStrategy) {
        this.defaultLoginProcessingUrl = defaultLoginProcessingUrl;
        this.filterClassName = filterClassName;
        this.requestCache = requestCache;
        this.sessionStrategy = sessionStrategy;
    }

    public BeanDefinition parse(Element elt, ParserContext pc) {
        String loginUrl = null;
        String defaultTargetUrl = null;
        String authenticationFailureUrl = null;
        String alwaysUseDefault = null;
        String successHandlerRef = null;
        String failureHandlerRef = null;

        Object source = null;

        if (elt != null) {
            source = pc.extractSource(elt);
            loginUrl = elt.getAttribute(ATT_LOGIN_URL);
            WebConfigUtils.validateHttpRedirect(loginUrl, pc, source);
            defaultTargetUrl = elt.getAttribute(ATT_FORM_LOGIN_TARGET_URL);
            WebConfigUtils.validateHttpRedirect(defaultTargetUrl, pc, source);
            authenticationFailureUrl = elt.getAttribute(ATT_FORM_LOGIN_AUTHENTICATION_FAILURE_URL);
            WebConfigUtils.validateHttpRedirect(authenticationFailureUrl, pc, source);
            alwaysUseDefault = elt.getAttribute(ATT_ALWAYS_USE_DEFAULT_TARGET_URL);
            loginPage = elt.getAttribute(ATT_LOGIN_PAGE);
            successHandlerRef = elt.getAttribute(ATT_SUCCESS_HANDLER_REF);
            failureHandlerRef = elt.getAttribute(ATT_FAILURE_HANDLER_REF);

            if (!StringUtils.hasText(loginPage)) {
                loginPage = null;
            }
            WebConfigUtils.validateHttpRedirect(loginPage, pc, source);
        }

        filterBean = createFilterBean(loginUrl, defaultTargetUrl, alwaysUseDefault, loginPage, authenticationFailureUrl,
                successHandlerRef, failureHandlerRef);
        filterBean.setSource(source);

        BeanDefinitionBuilder entryPointBuilder =
                BeanDefinitionBuilder.rootBeanDefinition(LoginUrlAuthenticationEntryPoint.class);
        entryPointBuilder.getRawBeanDefinition().setSource(source);
        entryPointBuilder.addPropertyValue("loginFormUrl", loginPage != null ? loginPage : DEF_LOGIN_PAGE);
        entryPointBean = (RootBeanDefinition) entryPointBuilder.getBeanDefinition();

        return null;
    }

    private RootBeanDefinition createFilterBean(String loginUrl, String defaultTargetUrl, String alwaysUseDefault,
            String loginPage, String authenticationFailureUrl, String successHandlerRef, String failureHandlerRef) {

        BeanDefinitionBuilder filterBuilder = BeanDefinitionBuilder.rootBeanDefinition(filterClassName);

        if (!StringUtils.hasText(loginUrl)) {
            loginUrl = defaultLoginProcessingUrl;
        }

        filterBuilder.addPropertyValue("filterProcessesUrl", loginUrl);

        if (StringUtils.hasText(successHandlerRef)) {
            filterBuilder.addPropertyReference("authenticationSuccessHandler", successHandlerRef);
        } else {
            BeanDefinitionBuilder successHandler = BeanDefinitionBuilder.rootBeanDefinition(SavedRequestAwareAuthenticationSuccessHandler.class);
            if ("true".equals(alwaysUseDefault)) {
                successHandler.addPropertyValue("alwaysUseDefaultTargetUrl", Boolean.TRUE);
            }
            successHandler.addPropertyValue("requestCache", requestCache);
            successHandler.addPropertyValue("defaultTargetUrl", StringUtils.hasText(defaultTargetUrl) ? defaultTargetUrl : DEF_FORM_LOGIN_TARGET_URL);
            filterBuilder.addPropertyValue("authenticationSuccessHandler", successHandler.getBeanDefinition());
        }

        if (sessionStrategy != null) {
            filterBuilder.addPropertyValue("sessionAuthenticationStrategy", sessionStrategy);
        }

        if (StringUtils.hasText(failureHandlerRef)) {
            filterBuilder.addPropertyReference("authenticationFailureHandler", failureHandlerRef);
        } else {
            BeanDefinitionBuilder failureHandler = BeanDefinitionBuilder.rootBeanDefinition(SimpleUrlAuthenticationFailureHandler.class);
            if (!StringUtils.hasText(authenticationFailureUrl)) {
                // Fall back to redisplaying the custom login page, if one was specified.
                if (StringUtils.hasText(loginPage)) {
                    authenticationFailureUrl = loginPage;
                } else {
                    authenticationFailureUrl = DEF_FORM_LOGIN_AUTHENTICATION_FAILURE_URL;
                }
            }
            failureHandler.addPropertyValue("defaultFailureUrl", authenticationFailureUrl);
            filterBuilder.addPropertyValue("authenticationFailureHandler", failureHandler.getBeanDefinition());
        }

        return (RootBeanDefinition) filterBuilder.getBeanDefinition();
    }

    RootBeanDefinition getFilterBean() {
        return filterBean;
    }

    RootBeanDefinition getEntryPointBean() {
        return entryPointBean;
    }

    String getLoginPage() {
        return loginPage;
    }
}
