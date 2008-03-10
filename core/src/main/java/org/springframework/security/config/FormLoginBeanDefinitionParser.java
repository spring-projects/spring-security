package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.ui.webapp.AuthenticationProcessingFilter;
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

    static final String ATT_LOGIN_URL = "login-processing-url";
    static final String DEF_LOGIN_URL = "/j_spring_security_check";

    static final String ATT_LOGIN_PAGE = "login-page";
    static final String DEF_LOGIN_PAGE = DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL;

    static final String ATT_FORM_LOGIN_TARGET_URL = "default-target-url";
    static final String DEF_FORM_LOGIN_TARGET_URL = "/";

    static final String ATT_FORM_LOGIN_AUTHENTICATION_FAILURE_URL = "authentication-failure-url";
    static final String DEF_FORM_LOGIN_AUTHENTICATION_FAILURE_URL = DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL + "?" + DefaultLoginPageGeneratingFilter.ERROR_PARAMETER_NAME;

    public BeanDefinition parse(Element elt, ParserContext parserContext) {
        String loginUrl = null;
        String defaultTargetUrl = null;
        String authenticationFailureUrl = null;
        String loginPage = null;
        Object source = null;

        if (elt != null) {
            loginUrl = elt.getAttribute(ATT_LOGIN_URL);
            defaultTargetUrl = elt.getAttribute(ATT_FORM_LOGIN_TARGET_URL);
            authenticationFailureUrl = elt.getAttribute(ATT_FORM_LOGIN_AUTHENTICATION_FAILURE_URL);
            loginPage = elt.getAttribute(ATT_LOGIN_PAGE);
            source = parserContext.extractSource(elt);
        }

        ConfigUtils.registerProviderManagerIfNecessary(parserContext);
        
        RootBeanDefinition filterBean = createFilterBean(loginUrl, defaultTargetUrl, loginPage, authenticationFailureUrl);

        filterBean.setSource(source);
        filterBean.getPropertyValues().addPropertyValue("authenticationManager",
                new RuntimeBeanReference(BeanIds.AUTHENTICATION_MANAGER));

        BeanDefinitionBuilder entryPointBuilder =
                BeanDefinitionBuilder.rootBeanDefinition(AuthenticationProcessingFilterEntryPoint.class);
        entryPointBuilder.setSource(source);


        // If no login page has been defined, add in the default page generator.
        if (!StringUtils.hasText(loginPage)) {
            logger.info("No login page configured in form-login element. The default internal one will be used. Use" +
                    "the 'loginPage' attribute to specify the URL of the login page.");
            loginPage = DEF_LOGIN_PAGE;
            RootBeanDefinition loginPageFilter = new RootBeanDefinition(DefaultLoginPageGeneratingFilter.class);
            loginPageFilter.getConstructorArgumentValues().addGenericArgumentValue(
                    new RuntimeBeanReference(BeanIds.FORM_LOGIN_FILTER));
            parserContext.getRegistry().registerBeanDefinition(BeanIds.DEFAULT_LOGIN_PAGE_GENERATING_FILTER, loginPageFilter);
        }

        entryPointBuilder.addPropertyValue("loginFormUrl", loginPage);

        parserContext.getRegistry().registerBeanDefinition(BeanIds.FORM_LOGIN_FILTER, filterBean);
        parserContext.getRegistry().registerBeanDefinition(BeanIds.FORM_LOGIN_ENTRY_POINT,
                entryPointBuilder.getBeanDefinition());

        return null;
    }

    private RootBeanDefinition createFilterBean(String loginUrl, String defaultTargetUrl, String loginPage, String authenticationFailureUrl) {
        BeanDefinitionBuilder filterBuilder =
                BeanDefinitionBuilder.rootBeanDefinition(AuthenticationProcessingFilter.class);


        if (!StringUtils.hasText(loginUrl)) {
        	loginUrl = DEF_LOGIN_URL;
        }

        filterBuilder.addPropertyValue("filterProcessesUrl", loginUrl);


        if (!StringUtils.hasText(defaultTargetUrl)) {
            defaultTargetUrl = DEF_FORM_LOGIN_TARGET_URL;
        }

        filterBuilder.addPropertyValue("defaultTargetUrl", defaultTargetUrl);

        if (!StringUtils.hasText(authenticationFailureUrl)) {
        	// Fallback to redisplaying the custom login page, if one was specified
        	if (StringUtils.hasText(loginPage)) {
        		authenticationFailureUrl = loginPage;
        	} else {
                authenticationFailureUrl = DEF_FORM_LOGIN_AUTHENTICATION_FAILURE_URL;
        	}
        }

        filterBuilder.addPropertyValue("authenticationFailureUrl", authenticationFailureUrl);

        return (RootBeanDefinition) filterBuilder.getBeanDefinition();
    }
}
