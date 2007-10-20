package org.springframework.security.config;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionDecorator;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.intercept.web.FilterChainMap;
import org.springframework.security.util.RegexUrlPathMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Sets the FilterChainMap for a FilterChainProxy bean declaration.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class FilterChainMapBeanDefinitionDecorator implements BeanDefinitionDecorator {
    public static final String FILTER_CHAIN_ELT_NAME = "filter-chain";

    public BeanDefinitionHolder decorate(Node node, BeanDefinitionHolder definition, ParserContext parserContext) {
        FilterChainMap filterChainMap = new FilterChainMap();
        Element elt = (Element)node;

        String pathType = elt.getAttribute(HttpSecurityBeanDefinitionParser.PATTERN_TYPE_ATTRIBUTE);

        if (HttpSecurityBeanDefinitionParser.PATTERN_TYPE_REGEX.equals(pathType)) {
            filterChainMap.setUrlPathMatcher(new RegexUrlPathMatcher());
        }

        List paths = new ArrayList();
        List filterChains = new ArrayList();

        Iterator filterChainElts = DomUtils.getChildElementsByTagName(elt, FILTER_CHAIN_ELT_NAME).iterator();

        while (filterChainElts.hasNext()) {
            Element chain = (Element) filterChainElts.next();
            String path = chain.getAttribute(HttpSecurityBeanDefinitionParser.PATH_PATTERN_ATTRIBUTE);
            Assert.hasText(path, "The attribute '" + HttpSecurityBeanDefinitionParser.PATH_PATTERN_ATTRIBUTE + "' must not be empty");
            String filters = chain.getAttribute(HttpSecurityBeanDefinitionParser.FILTERS_ATTRIBUTE);
            Assert.hasText(filters, "The attribute '" + HttpSecurityBeanDefinitionParser.FILTERS_ATTRIBUTE +
                    "'must not be empty");
            paths.add(path);
            filterChains.add(filters);
        }

        // Set the FilterChainMap on the FilterChainProxy bean.
        definition.getBeanDefinition().getPropertyValues().addPropertyValue("filterChainMap", filterChainMap);

        // Register the ApplicationContextAware bean which will add the filter chains to the FilterChainMap
        RootBeanDefinition chainResolver = new RootBeanDefinition(FilterChainResolver.class);
        chainResolver.getConstructorArgumentValues().addIndexedArgumentValue(0, filterChainMap);
        chainResolver.getConstructorArgumentValues().addIndexedArgumentValue(1, paths);
        chainResolver.getConstructorArgumentValues().addIndexedArgumentValue(2, filterChains);

        parserContext.getRegistry().registerBeanDefinition(definition.getBeanName() + ".filterChainMapChainResolver",
                chainResolver);

        return definition;
    }

    /**
     * Bean which stores the filter chains as lists of bean names (e.g.
     * "filter1, filter2, filter3") until the application context is available, then resolves them
     * to actual Filter instances when the <tt>setApplicationContext</tt> method is called.
     * It then uses them to build the secure URL configuration for the supplied FilterChainMap.
     */
    static class FilterChainResolver implements ApplicationContextAware {
        private List paths;
        private List filterChains;
        FilterChainMap filterChainMap;

        FilterChainResolver(FilterChainMap filterChainMap, List paths, List filterChains) {
            this.paths = paths;
            this.filterChains = filterChains;
            this.filterChainMap = filterChainMap;
        }

        public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
            for (int i=0; i < paths.size(); i++) {
                String path = (String)paths.get(i);
                String filterList = (String) filterChains.get(i);

                if (filterList.equals(HttpSecurityBeanDefinitionParser.NO_FILTERS_VALUE)) {
                    filterChainMap.addSecureUrl(path, HttpSecurityBeanDefinitionParser.EMPTY_FILTER_CHAIN);
                } else {
                    String[] filterNames = StringUtils.tokenizeToStringArray(filterList, ",");
                    Filter[] filters = new Filter[filterNames.length];

                    for (int j=0; j < filterNames.length; j++) {
                        filters[j] = (Filter) applicationContext.getBean(filterNames[j], Filter.class);
                    }

                    filterChainMap.addSecureUrl(path, filters);
                }
            }
        }
    }
}
