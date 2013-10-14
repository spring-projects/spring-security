package org.springframework.security.config.http;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.security.web.util.matchers.AntPathRequestMatcher;
import org.springframework.security.web.util.matchers.AnyRequestMatcher;
import org.springframework.security.web.util.matchers.RegexRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * Defines the {@link RequestMatcher} types supported by the namespace.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public enum MatcherType {
    ant (AntPathRequestMatcher.class),
    regex (RegexRequestMatcher.class),
    ciRegex (RegexRequestMatcher.class);

    private static final Log logger = LogFactory.getLog(MatcherType.class);

    private static final String ATT_MATCHER_TYPE = "request-matcher";
    private static final String ATT_PATH_TYPE = "path-type";

    private final Class<? extends RequestMatcher> type;

    MatcherType(Class<? extends RequestMatcher> type) {
        this.type = type;
    }

    public BeanDefinition createMatcher(String path, String method) {
        if (("/**".equals(path) || "**".equals(path)) && method == null) {
            return new RootBeanDefinition(AnyRequestMatcher.class);
        }

        BeanDefinitionBuilder matcherBldr = BeanDefinitionBuilder.rootBeanDefinition(type);

        matcherBldr.addConstructorArgValue(path);
        matcherBldr.addConstructorArgValue(method);

        if (this == ciRegex) {
             matcherBldr.addConstructorArgValue(true);
        }

        return matcherBldr.getBeanDefinition();
    }

    static MatcherType fromElement(Element elt) {
        if (StringUtils.hasText(elt.getAttribute(ATT_MATCHER_TYPE))) {
            return valueOf(elt.getAttribute(ATT_MATCHER_TYPE));
        }

        if (StringUtils.hasText(elt.getAttribute(ATT_PATH_TYPE))) {
            logger.warn("'" + ATT_PATH_TYPE + "' is deprecated. Please use '" + ATT_MATCHER_TYPE +"' instead.");
            return valueOf(elt.getAttribute(ATT_PATH_TYPE));
        }

        return ant;
    }
}
