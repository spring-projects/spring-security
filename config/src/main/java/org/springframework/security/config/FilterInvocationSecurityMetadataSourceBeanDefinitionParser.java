package org.springframework.security.config;

import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.util.AntUrlPathMatcher;
import org.springframework.security.util.UrlMatcher;
import org.springframework.security.web.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.intercept.RequestKey;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Allows for convenient creation of a {@link FilterInvocationSecurityMetadataSource} bean for use with a FilterSecurityInterceptor.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class FilterInvocationSecurityMetadataSourceBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

    protected String getBeanClassName(Element element) {
        return "org.springframework.security.web.intercept.DefaultFilterInvocationSecurityMetadataSource";
    }

    protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
        List<Element> interceptUrls = DomUtils.getChildElementsByTagName(element, "intercept-url");

        // Check for attributes that aren't allowed in this context
        for(Element elt : interceptUrls) {
            if (StringUtils.hasLength(elt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_REQUIRES_CHANNEL))) {
                parserContext.getReaderContext().error("The attribute '" + HttpSecurityBeanDefinitionParser.ATT_REQUIRES_CHANNEL + "' isn't allowed here.", elt);
            }

            if (StringUtils.hasLength(elt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_FILTERS))) {
                parserContext.getReaderContext().error("The attribute '" + HttpSecurityBeanDefinitionParser.ATT_FILTERS + "' isn't allowed here.", elt);
            }
        }

        UrlMatcher matcher = HttpSecurityBeanDefinitionParser.createUrlMatcher(element);
        boolean convertPathsToLowerCase = (matcher instanceof AntUrlPathMatcher) && matcher.requiresLowerCaseUrl();

        LinkedHashMap<RequestKey, List<ConfigAttribute>> requestMap =
        HttpSecurityBeanDefinitionParser.parseInterceptUrlsForFilterInvocationRequestMap(interceptUrls,
                convertPathsToLowerCase, false, parserContext);

        builder.addConstructorArgValue(matcher);
        builder.addConstructorArgValue(requestMap);
    }
}
