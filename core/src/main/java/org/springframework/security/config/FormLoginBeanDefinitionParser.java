package org.springframework.security.config;

import org.springframework.beans.PropertyValue;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.ui.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.ui.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.ui.webapp.AuthenticationProcessingFilterEntryPoint;
import org.springframework.security.ui.webapp.DefaultLoginPageGeneratingFilter;
import org.springframework.util.StringUtils;

import org.w3c.dom.Element;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * @author Luke Taylor
 * @author Ben Alex
 * @version $Id$
 */
public class FormLoginBeanDefinitionParser implements BeanDefinitionParser {
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

    private String defaultLoginProcessingUrl;
    private String filterClassName;

    private RootBeanDefinition filterBean;
    private RootBeanDefinition entryPointBean;
    private String loginPage;

    FormLoginBeanDefinitionParser(String defaultLoginProcessingUrl, String filterClassName) {
        this.defaultLoginProcessingUrl = defaultLoginProcessingUrl;
        this.filterClassName = filterClassName;
    }

    public BeanDefinition parse(Element elt, ParserContext pc) {
        String loginUrl = null;
        String defaultTargetUrl = null;
        String authenticationFailureUrl = null;
        String alwaysUseDefault = null;
        String successHandlerRef = null;
        String failureHandlerRef = null;

        Object source = null;

        // Copy values from the session fixation protection filter
        final Boolean sessionFixationProtectionEnabled =
            new Boolean(pc.getRegistry().containsBeanDefinition(BeanIds.SESSION_FIXATION_PROTECTION_FILTER));
        Boolean migrateSessionAttributes = Boolean.FALSE;

        if (sessionFixationProtectionEnabled.booleanValue()) {
            PropertyValue pv =
                    pc.getRegistry().getBeanDefinition(BeanIds.SESSION_FIXATION_PROTECTION_FILTER)
                        .getPropertyValues().getPropertyValue("migrateSessionAttributes");
            migrateSessionAttributes = (Boolean)pv.getValue();
        }

        if (elt != null) {
            source = pc.extractSource(elt);
            loginUrl = elt.getAttribute(ATT_LOGIN_URL);
            ConfigUtils.validateHttpRedirect(loginUrl, pc, source);
            defaultTargetUrl = elt.getAttribute(ATT_FORM_LOGIN_TARGET_URL);
            ConfigUtils.validateHttpRedirect(defaultTargetUrl, pc, source);
            authenticationFailureUrl = elt.getAttribute(ATT_FORM_LOGIN_AUTHENTICATION_FAILURE_URL);
            ConfigUtils.validateHttpRedirect(authenticationFailureUrl, pc, source);
            alwaysUseDefault = elt.getAttribute(ATT_ALWAYS_USE_DEFAULT_TARGET_URL);
            loginPage = elt.getAttribute(ATT_LOGIN_PAGE);
            successHandlerRef = elt.getAttribute(ATT_SUCCESS_HANDLER_REF);
            failureHandlerRef = elt.getAttribute(ATT_FAILURE_HANDLER_REF);

            if (!StringUtils.hasText(loginPage)) {
                loginPage = null;
            }
            ConfigUtils.validateHttpRedirect(loginPage, pc, source);
        }

        ConfigUtils.registerProviderManagerIfNecessary(pc);

        filterBean = createFilterBean(loginUrl, defaultTargetUrl, alwaysUseDefault, loginPage, authenticationFailureUrl,
                successHandlerRef, failureHandlerRef);
        filterBean.setSource(source);
        filterBean.getPropertyValues().addPropertyValue("authenticationManager",
                new RuntimeBeanReference(BeanIds.AUTHENTICATION_MANAGER));

        filterBean.getPropertyValues().addPropertyValue("invalidateSessionOnSuccessfulAuthentication",
                sessionFixationProtectionEnabled);
        filterBean.getPropertyValues().addPropertyValue("migrateInvalidatedSessionAttributes",
                migrateSessionAttributes);

        if (pc.getRegistry().containsBeanDefinition(BeanIds.REMEMBER_ME_SERVICES)) {
            filterBean.getPropertyValues().addPropertyValue("rememberMeServices",
                    new RuntimeBeanReference(BeanIds.REMEMBER_ME_SERVICES) );
        }

        if (pc.getRegistry().containsBeanDefinition(BeanIds.SESSION_REGISTRY)) {
            filterBean.getPropertyValues().addPropertyValue("sessionRegistry",
                    new RuntimeBeanReference(BeanIds.SESSION_REGISTRY));
        }

        BeanDefinitionBuilder entryPointBuilder =
                BeanDefinitionBuilder.rootBeanDefinition(AuthenticationProcessingFilterEntryPoint.class);
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
            successHandler.addPropertyValue("defaultTargetUrl", StringUtils.hasText(defaultTargetUrl) ? defaultTargetUrl : DEF_FORM_LOGIN_TARGET_URL);
            filterBuilder.addPropertyValue("authenticationSuccessHandler", successHandler.getBeanDefinition());
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
