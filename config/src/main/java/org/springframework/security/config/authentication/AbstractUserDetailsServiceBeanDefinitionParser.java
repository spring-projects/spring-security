package org.springframework.security.config.authentication;

import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.Elements;
import org.springframework.util.StringUtils;

import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 */
public abstract class AbstractUserDetailsServiceBeanDefinitionParser implements BeanDefinitionParser {
    static final String CACHE_REF = "cache-ref";
    public static final String CACHING_SUFFIX = ".caching";

    /**  UserDetailsService bean Id. For use in a stateful context (i.e. in AuthenticationProviderBDP) */
    private String id;

    protected abstract String getBeanClassName(Element element);

    protected abstract void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder);

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(getBeanClassName(element));

        doParse(element, parserContext, builder);

        RootBeanDefinition userService = (RootBeanDefinition) builder.getBeanDefinition();
        final String beanId = resolveId(element, userService, parserContext);

        parserContext.registerBeanComponent(new BeanComponentDefinition(userService, beanId));

        String cacheRef = element.getAttribute(CACHE_REF);

        // Register a caching version of the user service if there's a cache-ref
        if (StringUtils.hasText(cacheRef)) {
            BeanDefinitionBuilder cachingUSBuilder = BeanDefinitionBuilder.rootBeanDefinition(CachingUserDetailsService.class);
            cachingUSBuilder.addConstructorArgReference(beanId);

            cachingUSBuilder.addPropertyValue("userCache", new RuntimeBeanReference(cacheRef));
            BeanDefinition cachingUserService = cachingUSBuilder.getBeanDefinition();
            parserContext.registerBeanComponent(new BeanComponentDefinition(cachingUserService, beanId + CACHING_SUFFIX));
        }

        id = beanId;

        return null;
    }

    private String resolveId(Element element, AbstractBeanDefinition definition, ParserContext parserContext)
            throws BeanDefinitionStoreException {

        String id = element.getAttribute("id");

        if (StringUtils.hasText(id)) {
            return id;
        }

        if(Elements.AUTHENTICATION_PROVIDER.equals(element.getParentNode().getNodeName())) {
            return parserContext.getReaderContext().generateBeanName(definition);
        }

        // If top level, use the default name or throw an exception if already used
        if (parserContext.getRegistry().containsBeanDefinition(BeanIds.USER_DETAILS_SERVICE)) {
            throw new BeanDefinitionStoreException("No id supplied and another " +
                    "bean is already registered as " + BeanIds.USER_DETAILS_SERVICE);
        }

        return BeanIds.USER_DETAILS_SERVICE;
    }

    String getId() {
        return id;
    }
}
