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
 * @version $Id$
 */
public class FormLoginBeanDefinitionParser implements BeanDefinitionParser {
    protected final Log logger = LogFactory.getLog(getClass());

    public static final String DEFAULT_FORM_LOGIN_FILTER_ID = "_formLoginFilter";
    public static final String DEFAULT_FORM_LOGIN_ENTRY_POINT_ID = "_formLoginEntryPoint";

    private static final String LOGIN_URL_ATTRIBUTE = "loginUrl";
    private static final String LOGIN_PAGE_ATTRIBUTE = "loginPage";

    private static final String FORM_LOGIN_TARGET_URL_ATTRIBUTE = "defaultTargetUrl";
    private static final String DEFAULT_FORM_LOGIN_TARGET_URL = "/";

    private static final String FORM_LOGIN_AUTH_FAILURE_URL_ATTRIBUTE = "defaultTargetUrl";
    // TODO: Change AbstractProcessingFilter to not need a failure URL and just write a failure message
    // to the response if one isn't set.
    private static final String DEFAULT_FORM_LOGIN_AUTH_FAILURE_URL = "/loginError";


    public BeanDefinition parse(Element elt, ParserContext parserContext) {
        ConfigUtils.registerProviderManagerIfNecessary(parserContext);

        BeanDefinition filterBean = createFilterBean(elt);

        filterBean.getPropertyValues().addPropertyValue("authenticationManager",
                new RuntimeBeanReference(ConfigUtils.DEFAULT_AUTH_MANAGER_ID));

        BeanDefinitionBuilder entryPointBuilder =
                BeanDefinitionBuilder.rootBeanDefinition(AuthenticationProcessingFilterEntryPoint.class);

        String loginPage = elt.getAttribute(LOGIN_PAGE_ATTRIBUTE);

        // If no login page has been defined, add in the default page generator.
        if (!StringUtils.hasText(loginPage)) {
            logger.info("No login page configured in form-login element. The default internal one will be used. Use" +
                    "the 'loginPage' attribute to specify the URL of the login page.");
            loginPage = DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL;
            RootBeanDefinition loginPageFilter = new RootBeanDefinition(DefaultLoginPageGeneratingFilter.class);
            loginPageFilter.getConstructorArgumentValues().addGenericArgumentValue(
                    new RuntimeBeanReference(DEFAULT_FORM_LOGIN_FILTER_ID));
            parserContext.getRegistry().registerBeanDefinition("_springSecurityLoginPageFilter", loginPageFilter);
        }

        entryPointBuilder.addPropertyValue("loginFormUrl", loginPage);

        parserContext.getRegistry().registerBeanDefinition(DEFAULT_FORM_LOGIN_FILTER_ID, filterBean);
        parserContext.getRegistry().registerBeanDefinition(DEFAULT_FORM_LOGIN_ENTRY_POINT_ID,
                entryPointBuilder.getBeanDefinition());

        return null;
    }

    private BeanDefinition createFilterBean(Element elt) {
        BeanDefinitionBuilder filterBuilder =
                BeanDefinitionBuilder.rootBeanDefinition(AuthenticationProcessingFilter.class);

        String loginUrl = elt.getAttribute(LOGIN_URL_ATTRIBUTE);

        if (StringUtils.hasText(loginUrl)) {
            filterBuilder.addPropertyValue("filterProcessesUrl", loginUrl);
        }

        String defaultTargetUrl = elt.getAttribute(FORM_LOGIN_TARGET_URL_ATTRIBUTE);

        if (!StringUtils.hasText(defaultTargetUrl)) {
            defaultTargetUrl = DEFAULT_FORM_LOGIN_TARGET_URL;
        }

        filterBuilder.addPropertyValue("defaultTargetUrl", defaultTargetUrl);

        String authenticationFailureUrl = elt.getAttribute(FORM_LOGIN_AUTH_FAILURE_URL_ATTRIBUTE);

        if (!StringUtils.hasText(authenticationFailureUrl)) {
            authenticationFailureUrl = DEFAULT_FORM_LOGIN_AUTH_FAILURE_URL;
        }

        filterBuilder.addPropertyValue("authenticationFailureUrl", authenticationFailureUrl);

        return filterBuilder.getBeanDefinition();
    }
}
