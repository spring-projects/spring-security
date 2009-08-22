package org.springframework.security.config.http;

import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.RequestKey;
import org.springframework.security.web.util.AntUrlPathMatcher;
import org.springframework.security.web.util.UrlMatcher;
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

    private static final String ATT_HTTP_METHOD = "method";
    private static final String ATT_PATTERN = "pattern";
    private static final String ATT_ACCESS = "access";
    private static final Log logger = LogFactory.getLog(FilterInvocationSecurityMetadataSourceBeanDefinitionParser.class);

    protected String getBeanClassName(Element element) {
        return "org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource";
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

        ManagedMap<BeanDefinition, BeanDefinition> requestMap = parseInterceptUrlsForFilterInvocationRequestMap(
                interceptUrls, convertPathsToLowerCase, false, parserContext);

        builder.addConstructorArgValue(matcher);
        builder.addConstructorArgValue(requestMap);
    }

    static ManagedMap<BeanDefinition, BeanDefinition> parseInterceptUrlsForFilterInvocationRequestMap(List<Element> urlElts,
            boolean useLowerCasePaths, boolean useExpressions, ParserContext parserContext) {

        ManagedMap<BeanDefinition, BeanDefinition> filterInvocationDefinitionMap = new ManagedMap<BeanDefinition, BeanDefinition>();

        for (Element urlElt : urlElts) {
            String access = urlElt.getAttribute(ATT_ACCESS);
            if (!StringUtils.hasText(access)) {
                continue;
            }

            String path = urlElt.getAttribute(ATT_PATTERN);

            if(!StringUtils.hasText(path)) {
                parserContext.getReaderContext().error("path attribute cannot be empty or null", urlElt);
            }

            if (useLowerCasePaths) {
                path = path.toLowerCase();
            }

            String method = urlElt.getAttribute(ATT_HTTP_METHOD);
            if (!StringUtils.hasText(method)) {
                method = null;
            }

            // Use beans to

            BeanDefinitionBuilder keyBldr = BeanDefinitionBuilder.rootBeanDefinition(RequestKey.class);
            keyBldr.addConstructorArgValue(path);
            keyBldr.addConstructorArgValue(method);

            BeanDefinitionBuilder attributeBuilder = BeanDefinitionBuilder.rootBeanDefinition(SecurityConfig.class);
            attributeBuilder.addConstructorArgValue(access);

            if (useExpressions) {
                logger.info("Creating access control expression attribute '" + access + "' for " + path);
                // The expression will be parsed later by the ExpressionFilterInvocationSecurityMetadataSource
                attributeBuilder.setFactoryMethod("createList");

            } else {
                attributeBuilder.setFactoryMethod("createListFromCommaDelimitedString");
            }

            BeanDefinition key = keyBldr.getBeanDefinition();

            if (filterInvocationDefinitionMap.containsKey(key)) {
                logger.warn("Duplicate URL defined: " + path + ". The original attribute values will be overwritten");
            }

            filterInvocationDefinitionMap.put(key, attributeBuilder.getBeanDefinition());
        }

        return filterInvocationDefinitionMap;
    }
}
