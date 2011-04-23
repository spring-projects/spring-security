package org.springframework.security.config.http;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

import java.util.*;

/**
 * @author Luke Taylor
 */
public class FilterChainBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

    @Override
    protected Class getBeanClass(Element element) {
        return SecurityFilterChain.class;
    }

    @Override
    protected void doParse(Element elt, BeanDefinitionBuilder builder) {
        MatcherType matcherType = MatcherType.fromElement(elt);
        String path = elt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_PATH_PATTERN);
        String filters = elt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_FILTERS);

        builder.addConstructorArgValue(matcherType.createMatcher(path, null));

        if (filters.equals(HttpSecurityBeanDefinitionParser.OPT_FILTERS_NONE)) {
            builder.addConstructorArgValue(Collections.EMPTY_LIST);
        } else {
            String[] filterBeanNames = StringUtils.tokenizeToStringArray(filters, ",");
            ManagedList<RuntimeBeanReference> filterChain = new ManagedList<RuntimeBeanReference>(filterBeanNames.length);

            for (String name : filterBeanNames) {
                filterChain.add(new RuntimeBeanReference(name));
            }

            builder.addConstructorArgValue(filterChain);
        }
    }
}
