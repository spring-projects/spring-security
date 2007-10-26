package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.ConfigAttributeEditor;
import org.springframework.security.context.HttpSessionContextIntegrationFilter;
import org.springframework.security.intercept.web.FilterInvocationDefinitionMap;
import org.springframework.security.intercept.web.FilterSecurityInterceptor;
import org.springframework.security.intercept.web.PathBasedFilterInvocationDefinitionMap;
import org.springframework.security.intercept.web.RegExpBasedFilterInvocationDefinitionMap;
import org.springframework.security.ui.ExceptionTranslationFilter;
import org.springframework.security.util.FilterChainProxy;
import org.springframework.security.util.RegexUrlPathMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

import javax.servlet.Filter;
import java.util.*;

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

    public static final String LOGOUT_ELEMENT = "logout";
    public static final String FORM_LOGIN_ELEMENT = "form-login";
    public static final String BASIC_AUTH_ELEMENT = "http-basic";    

    static final String PATH_PATTERN_ATTRIBUTE = "pattern";
    static final String PATTERN_TYPE_ATTRIBUTE = "pathType";
    static final String PATTERN_TYPE_REGEX = "regex";

    static final String FILTERS_ATTRIBUTE = "filters";
    static final String NO_FILTERS_VALUE = "none";

    private static final String ACCESS_CONFIG_ATTRIBUTE = "access";

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

        if (patternType.equals(PATTERN_TYPE_REGEX)) {
            filterChainProxy.getPropertyValues().addPropertyValue("matcher", new RegexUrlPathMatcher());
            interceptorFilterInvDefSource = new RegExpBasedFilterInvocationDefinitionMap();
        }

        filterChainProxy.getPropertyValues().addPropertyValue("filterChainMap", filterChainMap);

        filterSecurityInterceptorBuilder.addPropertyValue("objectDefinitionSource", interceptorFilterInvDefSource);

        // Again pick up auth manager
        //filterSecurityInterceptorBuilder.setAutowireMode(RootBeanDefinition.AUTOWIRE_BY_TYPE);

        parseInterceptUrls(DomUtils.getChildElementsByTagName(element, "intercept-url"),
                filterChainMap, interceptorFilterInvDefSource);
        // TODO: if empty, set a default set a default /**, omitting login url

        BeanDefinitionRegistry registry = parserContext.getRegistry();

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
            FilterInvocationDefinitionMap interceptorFilterInvDefSource) {

        Iterator urlEltsIterator = urlElts.iterator();

        ConfigAttributeEditor attributeEditor = new ConfigAttributeEditor();

        while (urlEltsIterator.hasNext()) {
            Element urlElt = (Element) urlEltsIterator.next();

            String path = urlElt.getAttribute(PATH_PATTERN_ATTRIBUTE);

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
                if (!filters.equals(NO_FILTERS_VALUE)) {
                    throw new IllegalStateException("Currently only 'none' is supported as the custom filters attribute");
                }

                filterChainMap.put(path, Collections.EMPTY_LIST);
            }
        }
    }
}
