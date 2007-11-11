package org.springframework.security.config;

import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.ConfigAttributeEditor;
import org.springframework.security.context.HttpSessionContextIntegrationFilter;
import org.springframework.security.intercept.web.AbstractFilterInvocationDefinitionSource;
import org.springframework.security.intercept.web.FilterInvocationDefinitionMap;
import org.springframework.security.intercept.web.FilterSecurityInterceptor;
import org.springframework.security.intercept.web.PathBasedFilterInvocationDefinitionMap;
import org.springframework.security.intercept.web.RegExpBasedFilterInvocationDefinitionMap;
import org.springframework.security.securechannel.ChannelDecisionManagerImpl;
import org.springframework.security.securechannel.ChannelProcessingFilter;
import org.springframework.security.securechannel.InsecureChannelProcessor;
import org.springframework.security.securechannel.SecureChannelProcessor;
import org.springframework.security.ui.ExceptionTranslationFilter;
import org.springframework.security.util.FilterChainProxy;
import org.springframework.security.util.RegexUrlPathMatcher;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;

import org.w3c.dom.Element;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Sets up HTTP security: filter stack and protected URLs.
 *
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class HttpSecurityBeanDefinitionParser implements BeanDefinitionParser {

    public static final String DEFAULT_FILTER_CHAIN_PROXY_ID = "_filterChainProxy";

    public static final String DEFAULT_HTTP_SESSION_FILTER_ID = "_httpSessionContextIntegrationFilter";
    public static final String DEFAULT_LOGOUT_FILTER_ID = "_logoutFilter";
    public static final String DEFAULT_EXCEPTION_TRANSLATION_FILTER_ID = "_exceptionTranslationFilter";
    public static final String DEFAULT_FILTER_SECURITY_INTERCEPTOR_ID = "_filterSecurityInterceptor";
    public static final String DEFAULT_CHANNEL_PROCESSING_FILTER_ID = "_channelProcessingFilter";
    public static final String DEFAULT_CHANNEL_DECISION_MANAGER_ID = "_channelDecisionManager";

    public static final String CONCURRENT_SESSIONS_ELEMENT = "concurrent-session-control";
    public static final String LOGOUT_ELEMENT = "logout";
    public static final String FORM_LOGIN_ELEMENT = "form-login";
    public static final String BASIC_AUTH_ELEMENT = "http-basic";
    public static final String REMEMBER_ME_ELEMENT = "remember-me";

    static final String PATH_PATTERN_ATTRIBUTE = "pattern";
    static final String PATTERN_TYPE_ATTRIBUTE = "pathType";
    static final String PATTERN_TYPE_REGEX = "regex";

    static final String FILTERS_ATTRIBUTE = "filters";
    static final String NO_FILTERS_VALUE = "none";

    private static final String ACCESS_CONFIG_ATTRIBUTE = "access";
    private static final String REQUIRES_CHANNEL_ATTRIBUTE = "requiresChannel";

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        RootBeanDefinition filterChainProxy = new RootBeanDefinition(FilterChainProxy.class);
        RootBeanDefinition httpSCIF = new RootBeanDefinition(HttpSessionContextIntegrationFilter.class);

        //TODO: Set session creation parameters based on session-creation attribute

        BeanDefinitionBuilder filterSecurityInterceptorBuilder
                = BeanDefinitionBuilder.rootBeanDefinition(FilterSecurityInterceptor.class);

        BeanDefinitionBuilder exceptionTranslationFilterBuilder
                = BeanDefinitionBuilder.rootBeanDefinition(ExceptionTranslationFilter.class);

        // Autowire for entry point (for now)
        // TODO: Examine entry point beans in post processing and pick the correct one
        // i.e. form login or cas if defined, then any other non-basic, non-digest, then  basic or digest
        exceptionTranslationFilterBuilder.setAutowireMode(RootBeanDefinition.AUTOWIRE_BY_TYPE);

        // TODO: Get path type attribute and determine FilDefInvS class

        Map filterChainMap =  new LinkedHashMap();

        String patternType = element.getAttribute(PATTERN_TYPE_ATTRIBUTE);

        FilterInvocationDefinitionMap interceptorFilterInvDefSource = new PathBasedFilterInvocationDefinitionMap();
        FilterInvocationDefinitionMap channelFilterInvDefSource = new PathBasedFilterInvocationDefinitionMap();

        if (patternType.equals(PATTERN_TYPE_REGEX)) {
            filterChainProxy.getPropertyValues().addPropertyValue("matcher", new RegexUrlPathMatcher());
            interceptorFilterInvDefSource = new RegExpBasedFilterInvocationDefinitionMap();
            channelFilterInvDefSource = new RegExpBasedFilterInvocationDefinitionMap();
        }

        filterChainProxy.getPropertyValues().addPropertyValue("filterChainMap", filterChainMap);

        filterSecurityInterceptorBuilder.addPropertyValue("objectDefinitionSource", interceptorFilterInvDefSource);

        // Again pick up auth manager
        //filterSecurityInterceptorBuilder.setAutowireMode(RootBeanDefinition.AUTOWIRE_BY_TYPE);

        parseInterceptUrls(DomUtils.getChildElementsByTagName(element, "intercept-url"),
                filterChainMap, interceptorFilterInvDefSource, channelFilterInvDefSource, parserContext);

        BeanDefinitionRegistry registry = parserContext.getRegistry();

        // Check if we need to register the channel processing beans
        if (((AbstractFilterInvocationDefinitionSource)channelFilterInvDefSource).getMapSize() > 0) {
            // At least one channel requirement has been specified
            RootBeanDefinition channelFilter = new RootBeanDefinition(ChannelProcessingFilter.class);
            channelFilter.getPropertyValues().addPropertyValue("channelDecisionManager",
                    new RuntimeBeanReference(DEFAULT_CHANNEL_DECISION_MANAGER_ID));

            channelFilter.getPropertyValues().addPropertyValue("filterInvocationDefinitionSource",
                    channelFilterInvDefSource);
            RootBeanDefinition channelDecisionManager = new RootBeanDefinition(ChannelDecisionManagerImpl.class);
            List channelProcessors = new ArrayList(2);
            channelProcessors.add(new SecureChannelProcessor());
            channelProcessors.add(new InsecureChannelProcessor());
            channelDecisionManager.getPropertyValues().addPropertyValue("channelProcessors", channelProcessors);

            registry.registerBeanDefinition(DEFAULT_CHANNEL_PROCESSING_FILTER_ID, channelFilter);
            registry.registerBeanDefinition(DEFAULT_CHANNEL_DECISION_MANAGER_ID, channelDecisionManager);
        }

        Element sessionControlElt = DomUtils.getChildElementByTagName(element, CONCURRENT_SESSIONS_ELEMENT);

        if (sessionControlElt != null) {
            new ConcurrentSessionsBeanDefinitionParser().parse(sessionControlElt, parserContext);
        }

        // Parse remember me before logout as RememberMeServices is also a LogoutHandler implementation.


        Element rememberMeElt = DomUtils.getChildElementByTagName(element, REMEMBER_ME_ELEMENT);

        if (rememberMeElt != null) {
            new RememberMeBeanDefinitionParser().parse(rememberMeElt, parserContext);
        }

        Element logoutElt = DomUtils.getChildElementByTagName(element, LOGOUT_ELEMENT);

        if (logoutElt != null) {
            new LogoutBeanDefinitionParser().parse(logoutElt, parserContext);
        }

        Element formLoginElt = DomUtils.getChildElementByTagName(element, FORM_LOGIN_ELEMENT);

        if (formLoginElt != null) {
            new FormLoginBeanDefinitionParser().parse(formLoginElt, parserContext);
        }

        Element basicAuthElt = DomUtils.getChildElementByTagName(element, BASIC_AUTH_ELEMENT);

        if (basicAuthElt != null) {
            new BasicAuthenticationBeanDefinitionParser().parse(basicAuthElt, parserContext);
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
     * Parses the intercept-url elements and populates the FilterChainProxy's filter chain Map and the
     * FilterInvocationDefinitionSource used in FilterSecurityInterceptor.
     */
    private void parseInterceptUrls(List urlElts, Map filterChainMap,
            FilterInvocationDefinitionMap interceptorFilterInvDefSource,
            FilterInvocationDefinitionMap channelFilterInvDefSource, ParserContext parserContext) {

        Iterator urlEltsIterator = urlElts.iterator();

        ConfigAttributeEditor editor = new ConfigAttributeEditor();

        while (urlEltsIterator.hasNext()) {
            Element urlElt = (Element) urlEltsIterator.next();

            String path = urlElt.getAttribute(PATH_PATTERN_ATTRIBUTE);

            Assert.hasText(path, "path attribute cannot be empty or null");

            String access = urlElt.getAttribute(ACCESS_CONFIG_ATTRIBUTE);

            // Convert the comma-separated list of access attributes to a ConfigAttributeDefinition
            if (StringUtils.hasText(access)) {
                editor.setAsText(access);
                interceptorFilterInvDefSource.addSecureUrl(path, (ConfigAttributeDefinition) editor.getValue());
            }

            String requiredChannel = urlElt.getAttribute(REQUIRES_CHANNEL_ATTRIBUTE);

            if (StringUtils.hasText(requiredChannel)) {
                String channelConfigAttribute = null;

                if (requiredChannel.equals("https")) {
                    channelConfigAttribute = "REQUIRES_SECURE_CHANNEL";
                } else if (requiredChannel.equals("http")) {
                    channelConfigAttribute = "REQUIRES_INSECURE_CHANNEL";
                } else {
                    parserContext.getReaderContext().error("Unsupported channel " + requiredChannel, urlElt);
                }

                editor.setAsText(channelConfigAttribute);
                channelFilterInvDefSource.addSecureUrl(path, (ConfigAttributeDefinition) editor.getValue());
            }

            String filters = urlElt.getAttribute(FILTERS_ATTRIBUTE);

            if (StringUtils.hasText(filters)) {
                if (!filters.equals(NO_FILTERS_VALUE)) {
                    parserContext.getReaderContext().error("Currently only 'none' is supported as the custom " +
                            "filters attribute", urlElt);
                }

                filterChainMap.put(path, Collections.EMPTY_LIST);
            }
        }
    }
}
