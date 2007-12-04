package org.springframework.security.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.wrapper.SecurityContextHolderAwareRequestFilter;
import org.w3c.dom.Element;

/**
 * @author Ben Alex
 * @version $Id$
 */
public class ServletApiIntegrationBeanDefinitionParser implements BeanDefinitionParser {
	protected final Log logger = LogFactory.getLog(getClass());

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        BeanDefinition filter = new RootBeanDefinition(SecurityContextHolderAwareRequestFilter.class);
        parserContext.getRegistry().registerBeanDefinition(BeanIds.SECURITY_CONTEXT_HOLDER_AWARE_REQUEST_FILTER, filter);
        System.out.println("********************");
        return null;
    }
}
