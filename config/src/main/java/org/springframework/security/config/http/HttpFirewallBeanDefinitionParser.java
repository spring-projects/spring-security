package org.springframework.security.config.http;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanReference;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.BeanIds;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

import java.util.*;

/**
 * Injects the supplied {@code HttpFirewall} bean reference into the {@code FilterChainProxy}.
 *
 * @author Luke Taylor
 */
public class HttpFirewallBeanDefinitionParser implements BeanDefinitionParser {

    public BeanDefinition parse(Element element, ParserContext pc) {
        String ref = element.getAttribute("ref");

        if (!StringUtils.hasText(ref)) {
            pc.getReaderContext().error("ref attribute is required", pc.extractSource(element));
        }

        // Ensure the FCP is registered.
        HttpSecurityBeanDefinitionParser.registerFilterChainProxy(pc,
                new ManagedMap<BeanDefinition, BeanReference>(),
                pc.extractSource(element));
        BeanDefinition filterChainProxy = pc.getRegistry().getBeanDefinition(BeanIds.FILTER_CHAIN_PROXY);
        filterChainProxy.getPropertyValues().addPropertyValue("firewall", new RuntimeBeanReference(ref));

        return null;
    }
}
