package org.springframework.security.config.http;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

import java.util.*;

/**
 * @author Luke Taylor
 */
public class FilterChainBeanDefinitionParser implements BeanDefinitionParser {
    private static final String ATT_REQUEST_MATCHER_REF = "request-matcher-ref";

    public BeanDefinition parse(Element elt, ParserContext pc) {
        MatcherType matcherType = MatcherType.fromElement(elt);
        String path = elt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_PATH_PATTERN);
        String requestMatcher = elt.getAttribute(ATT_REQUEST_MATCHER_REF);
        String filters = elt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_FILTERS);

        BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(SecurityFilterChain.class);

        if (StringUtils.hasText(path)) {
            Assert.isTrue(!StringUtils.hasText(requestMatcher), "");
            builder.addConstructorArgValue(matcherType.createMatcher(path, null));
        } else {
            Assert.isTrue(StringUtils.hasText(requestMatcher), "");
            builder.addConstructorArgReference(requestMatcher);
        }

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

        return builder.getBeanDefinition();
    }
}
