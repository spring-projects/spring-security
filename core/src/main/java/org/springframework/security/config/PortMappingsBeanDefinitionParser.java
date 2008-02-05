package org.springframework.security.config;

import org.springframework.security.util.PortMapperImpl;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;

import org.w3c.dom.Element;

import java.util.List;
import java.util.Iterator;
import java.util.Map;
import java.util.HashMap;

/**
 * Parses a port-mappings element, producing a single {@link org.springframework.security.util.PortMapperImpl}
 * bean.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class PortMappingsBeanDefinitionParser implements BeanDefinitionParser {
    public static final String ATT_HTTP_PORT = "http";
    public static final String ATT_HTTPS_PORT = "https";

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        BeanDefinition portMapper = new RootBeanDefinition(PortMapperImpl.class);

        if (element != null) {
            List mappingElts = DomUtils.getChildElementsByTagName(element, Elements.PORT_MAPPING);
            if(mappingElts.isEmpty()) {
                parserContext.getReaderContext().error("No port-mapping child elements specified", element);
            }

            Map mappings = new HashMap();

            Iterator iterator = mappingElts.iterator();
            while (iterator.hasNext()) {
                Element elt = (Element) iterator.next();
                String httpPort = elt.getAttribute(ATT_HTTP_PORT);
                String httpsPort = elt.getAttribute(ATT_HTTPS_PORT);

                if (!StringUtils.hasText(httpPort)) {
                    parserContext.getReaderContext().error("No http port supplied in port mapping", elt);
                }

                if (!StringUtils.hasText(httpsPort)) {
                    parserContext.getReaderContext().error("No https port supplied in port mapping", elt);
                }

                mappings.put(httpPort, httpsPort);
            }

            portMapper.getPropertyValues().addPropertyValue("portMappings", mappings);
        }

        return portMapper;
    }
}
