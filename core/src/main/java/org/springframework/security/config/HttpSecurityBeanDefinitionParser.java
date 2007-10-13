package org.springframework.security.config;

import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.util.xml.DomUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.security.util.FilterChainProxy;
import org.springframework.security.intercept.web.PathBasedFilterInvocationDefinitionMap;
import org.springframework.security.intercept.web.FilterSecurityInterceptor;
import org.springframework.security.intercept.web.FilterInvocationDefinitionMap;
import org.springframework.security.ConfigAttributeEditor;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.ui.ExceptionTranslationFilter;
import org.springframework.security.ui.webapp.AuthenticationProcessingFilter;
import org.springframework.security.ui.webapp.AuthenticationProcessingFilterEntryPoint;
import org.springframework.security.context.HttpSessionContextIntegrationFilter;
import org.w3c.dom.Element;

import java.util.List;
import java.util.Iterator;

/**
 * Sets up HTTP security: filter stack and protected URLs.
 *
 *
 * @author luke
 * @version $Id$
 */
public class HttpSecurityBeanDefinitionParser implements BeanDefinitionParser {

    public static final String DEFAULT_FILTER_CHAIN_PROXY_ID = "_filterChainProxy";

    public static final String DEFAULT_HTTP_SESSION_FILTER_ID = "_httpSessionContextIntegrationFilter";
    public static final String DEFAULT_LOGOUT_FILTER_ID = "_logoutFilter";
    public static final String DEFAULT_EXCEPTION_TRANSLATION_FILTER_ID = "_exceptionTranslationFilter";
    public static final String DEFAULT_FILTER_SECURITY_INTERCEPTOR_ID = "_filterSecurityInterceptor";
    public static final String DEFAULT_FORM_LOGIN_FILTER_ID = "_formLoginFilter";
    public static final String DEFAULT_FORM_LOGIN_ENTRY_POINT_ID = "_formLoginEntryPoint";

    public static final String LOGOUT_ELEMENT = "logout";
    public static final String FORM_LOGIN_ELEMENT = "form-login";

    private static final String PATH_ATTRIBUTE = "path";
    private static final String FILTERS_ATTRIBUTE = "filters";
    private static final String ACCESS_CONFIG_ATTRIBUTE = "access";

    private static final String LOGIN_URL_ATTRIBUTE = "loginUrl";

    private static final String FORM_LOGIN_TARGET_URL_ATTRIBUTE = "defaultTargetUrl";
    private static final String DEFAULT_FORM_LOGIN_TARGET_URL = "/index";

    private static final String FORM_LOGIN_AUTH_FAILURE_URL_ATTRIBUTE = "defaultTargetUrl";
    // TODO: Change AbstractProcessingFilter to not need a failure URL and just write a failure message
    // to the response if one isn't set.
    private static final String DEFAULT_FORM_LOGIN_AUTH_FAILURE_URL = "/loginError";

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        // Create HttpSCIF, FilterInvocationInterceptor, ExceptionTranslationFilter

        // Find other filter beans.

        // Create appropriate bean list for config attributes to create FIDS

        // Add any secure URLs with specific filter chains to FIDS as separate ConfigAttributes

        // Add secure URLS with roles to objectDefinitionSource for FilterSecurityInterceptor

        RootBeanDefinition filterChainProxy = new RootBeanDefinition(FilterChainProxy.class);

        RootBeanDefinition httpSCIF = new RootBeanDefinition(HttpSessionContextIntegrationFilter.class);

        //TODO: Set session creation parameters based on session-creation attribute

        BeanDefinitionBuilder filterSecurityInterceptorBuilder
                = BeanDefinitionBuilder.rootBeanDefinition(FilterSecurityInterceptor.class);


        BeanDefinitionBuilder exceptionTranslationFilterBuilder
                = BeanDefinitionBuilder.rootBeanDefinition(ExceptionTranslationFilter.class);

        // Autowire for entry point (for now)
        exceptionTranslationFilterBuilder.setAutowireMode(RootBeanDefinition.AUTOWIRE_BY_TYPE);

        // TODO: Get path type attribute and determine FilDefInvS class
        PathBasedFilterInvocationDefinitionMap filterChainInvocationDefSource
                = new PathBasedFilterInvocationDefinitionMap();

        filterChainProxy.getPropertyValues().addPropertyValue("filterInvocationDefinitionSource",
                filterChainInvocationDefSource);

        PathBasedFilterInvocationDefinitionMap interceptorFilterInvDefSource
                = new PathBasedFilterInvocationDefinitionMap();

        filterSecurityInterceptorBuilder.addPropertyValue("objectDefinitionSource", interceptorFilterInvDefSource);

        // Again pick up auth manager
        filterSecurityInterceptorBuilder.setAutowireMode(RootBeanDefinition.AUTOWIRE_BY_TYPE);

        parseInterceptUrls(DomUtils.getChildElementsByTagName(element, "intercept-url"),
                filterChainInvocationDefSource, interceptorFilterInvDefSource);
        // TODO: if empty, set a default set a default /**, omitting login url

        BeanDefinitionRegistry registry = parserContext.getRegistry();

        Element logoutElt = DomUtils.getChildElementByTagName(element, LOGOUT_ELEMENT);

        if (logoutElt != null) {
            BeanDefinition logoutFilter = new LogoutBeanDefinitionParser().parse(logoutElt, parserContext);
        }

        Element formLoginElt = DomUtils.getChildElementByTagName(element, FORM_LOGIN_ELEMENT);

        if (formLoginElt != null) {
            BeanDefinitionBuilder formLoginFilterBuilder =
                    BeanDefinitionBuilder.rootBeanDefinition(AuthenticationProcessingFilter.class);
            BeanDefinitionBuilder formLoginEntryPointBuilder =
                    BeanDefinitionBuilder.rootBeanDefinition(AuthenticationProcessingFilterEntryPoint.class);

            // Temporary login value
            formLoginEntryPointBuilder.addPropertyValue("loginFormUrl", "/login");


            String loginUrl = formLoginElt.getAttribute(LOGIN_URL_ATTRIBUTE);

            if (StringUtils.hasText(loginUrl)) {
                formLoginFilterBuilder.addPropertyValue("filterProcessesUrl", loginUrl);
            }

            String defaultTargetUrl = formLoginElt.getAttribute(FORM_LOGIN_TARGET_URL_ATTRIBUTE);

            if (!StringUtils.hasText(defaultTargetUrl)) {
                defaultTargetUrl = DEFAULT_FORM_LOGIN_TARGET_URL;
            }

            formLoginFilterBuilder.addPropertyValue("defaultTargetUrl", defaultTargetUrl);

            String authenticationFailureUrl = formLoginElt.getAttribute(FORM_LOGIN_AUTH_FAILURE_URL_ATTRIBUTE);

            if (!StringUtils.hasText(authenticationFailureUrl)) {
                authenticationFailureUrl = DEFAULT_FORM_LOGIN_AUTH_FAILURE_URL;
            }

            formLoginFilterBuilder.addPropertyValue("authenticationFailureUrl", authenticationFailureUrl);
            // Set autowire to pick up the authentication manager.
            formLoginFilterBuilder.setAutowireMode(RootBeanDefinition.AUTOWIRE_BY_TYPE);


            registry.registerBeanDefinition(DEFAULT_FORM_LOGIN_FILTER_ID,
                    formLoginFilterBuilder.getBeanDefinition());
            registry.registerBeanDefinition(DEFAULT_FORM_LOGIN_ENTRY_POINT_ID,
                    formLoginEntryPointBuilder.getBeanDefinition());
        }

        registry.registerBeanDefinition(DEFAULT_FILTER_CHAIN_PROXY_ID, filterChainProxy);
        registry.registerBeanDefinition(DEFAULT_HTTP_SESSION_FILTER_ID, httpSCIF);
        registry.registerBeanDefinition(DEFAULT_EXCEPTION_TRANSLATION_FILTER_ID,
                exceptionTranslationFilterBuilder.getBeanDefinition());
        registry.registerBeanDefinition(DEFAULT_FILTER_SECURITY_INTERCEPTOR_ID,
                filterSecurityInterceptorBuilder.getBeanDefinition());


        // Register the post processor which will tie up the loose ends in the configuration once the
        // app context has been created and all beans are available.

        registry.registerBeanDefinition("__httpConfigBeanFactoryPostProcessor",
                new RootBeanDefinition(HttpSecurityConfigPostProcessor.class));        

        return null;
    }

    /**
     * Parses the intercept-url elements and populates the FilterChainProxy's FilterInvocationDefinitionSource
     */
    private void parseInterceptUrls(List urlElts, FilterInvocationDefinitionMap filterChainInvocationDefSource,
            FilterInvocationDefinitionMap interceptorFilterInvDefSource) {

        Iterator urlEltsIterator = urlElts.iterator();

        ConfigAttributeEditor attributeEditor = new ConfigAttributeEditor();

        while (urlEltsIterator.hasNext()) {
            Element urlElt = (Element) urlEltsIterator.next();

            String path = urlElt.getAttribute(PATH_ATTRIBUTE);

            Assert.hasText(path, "path attribute cannot be empty or null");

            String access = urlElt.getAttribute(ACCESS_CONFIG_ATTRIBUTE);

            // Convert the comma-separated list of access attributes to a ConfigAttributeDefinition
            if (StringUtils.hasText(access)) {
                attributeEditor.setAsText(access);

                ConfigAttributeDefinition attributeDef = (ConfigAttributeDefinition) attributeEditor.getValue();

                interceptorFilterInvDefSource.addSecureUrl(path, attributeDef);
            }

            String filters = urlElt.getAttribute(FILTERS_ATTRIBUTE);

            if (StringUtils.hasText(filters)) {
                attributeEditor.setAsText(filters);
            }



        }
    }
}
