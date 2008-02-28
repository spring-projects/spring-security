package org.springframework.security.config;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.util.AntUrlPathMatcher;
import org.springframework.security.util.UrlMatcher;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Allows for convenient creation of a {@link FilterInvocationDefinitionSource} bean for use with a FilterSecurityInterceptor.  
 * 
 * @author Luke Taylor
 * @version $Id$
 */
public class FilterInvocationDefinitionSourceBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

    protected String getBeanClassName(Element element) {
        return "org.springframework.security.intercept.web.DefaultFilterInvocationDefinitionSource";
    }

    protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
        List interceptUrls = DomUtils.getChildElementsByTagName(element, "intercept-url");
        
        // Check for attributes that aren't allowed in this context
        Iterator interceptUrlElts = interceptUrls.iterator();
        while(interceptUrlElts.hasNext()) {
            Element elt = (Element) interceptUrlElts.next();
            if (StringUtils.hasLength(elt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_REQUIRES_CHANNEL))) {
                parserContext.getReaderContext().error("The attribute '" + HttpSecurityBeanDefinitionParser.ATT_REQUIRES_CHANNEL + "' isn't allowed here.", elt);
            }

            if (StringUtils.hasLength(elt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_FILTERS))) {
                parserContext.getReaderContext().error("The attribute '" + HttpSecurityBeanDefinitionParser.ATT_FILTERS + "' isn't allowed here.", elt);
            }
        }

        UrlMatcher matcher = HttpSecurityBeanDefinitionParser.createUrlMatcher(element);
        boolean convertPathsToLowerCase = (matcher instanceof AntUrlPathMatcher) && matcher.requiresLowerCaseUrl();
        
        LinkedHashMap requestMap = new LinkedHashMap();
        HttpSecurityBeanDefinitionParser.parseInterceptUrlsForFilterInvocationRequestMap(interceptUrls, requestMap, 
                convertPathsToLowerCase, parserContext);
        
        builder.addConstructorArg(matcher);
        builder.addConstructorArg(requestMap);
    }
}
