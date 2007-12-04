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
 * @author Luke Taylor
 * @author Ben Alex
 * @version $Id$
 */
public class HttpSecurityBeanDefinitionParser implements BeanDefinitionParser {

    static final String ATT_REALM = "realm";
    static final String DEF_REALM = "Spring Security Application";

    static final String ATT_PATH_PATTERN = "pattern";
    static final String ATT_PATTERN_TYPE = "pathType";
    static final String ATT_PATTERN_TYPE_REGEX = "regex";

    static final String ATT_FILTERS = "filters";
    static final String NO_FILTERS_VALUE = "none";

    static final String ATT_ACCESS_CONFIG = "access";
    static final String ATT_REQUIRES_CHANNEL = "requiresChannel";

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

        String patternType = element.getAttribute(ATT_PATTERN_TYPE);

        FilterInvocationDefinitionMap interceptorFilterInvDefSource = new PathBasedFilterInvocationDefinitionMap();
        FilterInvocationDefinitionMap channelFilterInvDefSource = new PathBasedFilterInvocationDefinitionMap();

        if (patternType.equals(ATT_PATTERN_TYPE_REGEX)) {
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
                    new RuntimeBeanReference(BeanIds.CHANNEL_DECISION_MANAGER));

            channelFilter.getPropertyValues().addPropertyValue("filterInvocationDefinitionSource",
                    channelFilterInvDefSource);
            RootBeanDefinition channelDecisionManager = new RootBeanDefinition(ChannelDecisionManagerImpl.class);
            List channelProcessors = new ArrayList(2);
            channelProcessors.add(new SecureChannelProcessor());
            channelProcessors.add(new InsecureChannelProcessor());
            channelDecisionManager.getPropertyValues().addPropertyValue("channelProcessors", channelProcessors);

            registry.registerBeanDefinition(BeanIds.CHANNEL_PROCESSING_FILTER, channelFilter);
            registry.registerBeanDefinition(BeanIds.CHANNEL_DECISION_MANAGER, channelDecisionManager);
        }

        Element sessionControlElt = DomUtils.getChildElementByTagName(element, Elements.CONCURRENT_SESSIONS);

        if (sessionControlElt != null) {
            new ConcurrentSessionsBeanDefinitionParser().parse(sessionControlElt, parserContext);
        }

        Element anonymousElt = DomUtils.getChildElementByTagName(element, Elements.ANONYMOUS);
        
        if (anonymousElt != null) {
            new AnonymousBeanDefinitionParser().parse(anonymousElt, parserContext);
        }
        
        // Parse remember me before logout as RememberMeServices is also a LogoutHandler implementation.


        Element rememberMeElt = DomUtils.getChildElementByTagName(element, Elements.REMEMBER_ME);

        if (rememberMeElt != null) {
            new RememberMeBeanDefinitionParser().parse(rememberMeElt, parserContext);
        }

        Element logoutElt = DomUtils.getChildElementByTagName(element, Elements.LOGOUT);

        if (logoutElt != null) {
            new LogoutBeanDefinitionParser().parse(logoutElt, parserContext);
        }

        Element formLoginElt = DomUtils.getChildElementByTagName(element, Elements.FORM_LOGIN);

        if (formLoginElt != null) {
            new FormLoginBeanDefinitionParser().parse(formLoginElt, parserContext);
        }
        
        String realm = element.getAttribute(ATT_REALM);
        if (!StringUtils.hasText(realm)) {
        	realm = DEF_REALM;
        }

        Element basicAuthElt = DomUtils.getChildElementByTagName(element, Elements.BASIC_AUTH);

        if (basicAuthElt != null) {
            new BasicAuthenticationBeanDefinitionParser(realm).parse(basicAuthElt, parserContext);
        }

        registry.registerBeanDefinition(BeanIds.FILTER_CHAIN_PROXY, filterChainProxy);
        registry.registerBeanDefinition(BeanIds.HTTP_SESSION_CONTEXT_INTEGRATION_FILTER, httpSCIF);
        registry.registerBeanDefinition(BeanIds.EXCEPTION_TRANSLATION_FILTER,
                exceptionTranslationFilterBuilder.getBeanDefinition());
        registry.registerBeanDefinition(BeanIds.FILTER_SECURITY_INTERCEPTOR,
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

            String path = urlElt.getAttribute(ATT_PATH_PATTERN);

            Assert.hasText(path, "path attribute cannot be empty or null");

            String access = urlElt.getAttribute(ATT_ACCESS_CONFIG);

            // Convert the comma-separated list of access attributes to a ConfigAttributeDefinition
            if (StringUtils.hasText(access)) {
                editor.setAsText(access);
                interceptorFilterInvDefSource.addSecureUrl(path, (ConfigAttributeDefinition) editor.getValue());
            }

            String requiredChannel = urlElt.getAttribute(ATT_REQUIRES_CHANNEL);

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

            String filters = urlElt.getAttribute(ATT_FILTERS);

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
