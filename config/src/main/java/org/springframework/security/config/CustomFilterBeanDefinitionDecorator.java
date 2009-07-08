package org.springframework.security.config;

import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.xml.BeanDefinitionDecorator;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Node;

/**
 * No longer used in Spring Security 3, other than to report a warning. The &lt;custom-filter&gt; elements should
 * be placed within the &lt;http&gt; block. See SEC-1186.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class CustomFilterBeanDefinitionDecorator implements BeanDefinitionDecorator {

    public BeanDefinitionHolder decorate(Node node, BeanDefinitionHolder holder, ParserContext parserContext) {
        parserContext.getReaderContext().warning("The use of <custom-filter /> within a filter bean declaration " +
                "is not supported in Spring Security 3.0+. If you are using Spring 3.0+, you should be place the " +
                "<custom-filter /> element within the " +
                "<http> block in our configuration and add a 'ref' attribute which points to your filter bean",
                parserContext.extractSource(node));

        return holder;
    }
}
