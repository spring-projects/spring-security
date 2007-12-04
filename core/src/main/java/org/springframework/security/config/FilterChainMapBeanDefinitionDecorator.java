package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.xml.BeanDefinitionDecorator;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.util.RegexUrlPathMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.*;

/**
 * Sets the filter chain Map for a FilterChainProxy bean declaration.
 *
 * @author Luke Taylor
 * @version $Id$
 */
class FilterChainMapBeanDefinitionDecorator implements BeanDefinitionDecorator {
    public BeanDefinitionHolder decorate(Node node, BeanDefinitionHolder holder, ParserContext parserContext) {
        BeanDefinition filterChainProxy = holder.getBeanDefinition();

        Map filterChainMap = new LinkedHashMap();
        Element elt = (Element)node;

        String pathType = elt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_PATH_TYPE);

        if (HttpSecurityBeanDefinitionParser.OPT_PATH_TYPE_REGEX.equals(pathType)) {
            filterChainProxy.getPropertyValues().addPropertyValue("matcher", new RegexUrlPathMatcher());
        }

        Iterator filterChainElts = DomUtils.getChildElementsByTagName(elt, Elements.FILTER_CHAIN).iterator();

        while (filterChainElts.hasNext()) {
            Element chain = (Element) filterChainElts.next();
            String path = chain.getAttribute(HttpSecurityBeanDefinitionParser.ATT_PATH_PATTERN);
            Assert.hasText(path, "The attribute '" + HttpSecurityBeanDefinitionParser.ATT_PATH_PATTERN +
                    "' must not be empty");
            String filters = chain.getAttribute(HttpSecurityBeanDefinitionParser.ATT_FILTERS);
            Assert.hasText(filters, "The attribute '" + HttpSecurityBeanDefinitionParser.ATT_FILTERS +
                    "'must not be empty");

            if (filters.equals(HttpSecurityBeanDefinitionParser.OPT_FILTERS_NONE)) {
                filterChainMap.put(path, Collections.EMPTY_LIST);
            } else {
                String[] filterBeanNames = StringUtils.tokenizeToStringArray(filters, ",");
                ManagedList filterChain = new ManagedList(filterBeanNames.length);

                for (int i=0; i < filterBeanNames.length; i++) {
                    filterChain.add(new RuntimeBeanReference(filterBeanNames[i]));
                }

                filterChainMap.put(path, filterChain);
            }
        }

        filterChainProxy.getPropertyValues().addPropertyValue("filterChainMap", new ManagedMap(filterChainMap));

        return holder;
    }
}
