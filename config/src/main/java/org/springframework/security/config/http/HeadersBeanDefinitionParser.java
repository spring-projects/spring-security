/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.http;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.web.headers.HeadersFilter;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Parser for the {@code HeadersFilter}.
 *
 * @author Marten Deinum
 * @since 3.2
 */
public class HeadersBeanDefinitionParser implements BeanDefinitionParser {

    private static final String ATT_ENABLED = "enabled";
    private static final String ATT_BLOCK = "block";

    private static final String ATT_POLICY = "policy";
    private static final String ATT_ORIGIN = "origin";

    private static final String ATT_NAME = "name";
    private static final String ATT_VALUE = "value";

    private static final String XSS_ELEMENT = "xss-protection";
    private static final String CONTENT_TYPE_ELEMENT = "content-type-options";
    private static final String FRAME_OPTIONS_ELEMENT = "frame-options";
    private static final String GENERIC_HEADER_ELEMENT = "header";

    private static final String XSS_PROTECTION_HEADER = "X-XSS-Protection";
    private static final String FRAME_OPTIONS_HEADER = "X-Frame-Options";
    private static final String CONTENT_TYPE_OPTIONS_HEADER = "X-Content-Type-Options";

    private static final String ALLOW_FROM = "ALLOW-FROM";

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(HeadersFilter.class);
        final Map<String, String> headers = new HashMap<String, String>();

        parseXssElement(element, headers);
        parseFrameOptionsElement(element, parserContext, headers);
        parseContentTypeOptionsElement(element, headers);

        parseHeaderElements(element, headers);

        builder.addPropertyValue("headers", headers);
        return builder.getBeanDefinition();
    }

    private void parseHeaderElements(Element element, Map<String, String> headers) {
        List<Element> headerEtls = DomUtils.getChildElementsByTagName(element, GENERIC_HEADER_ELEMENT);
        for (Element headerEtl : headerEtls) {
            headers.put(headerEtl.getAttribute(ATT_NAME), headerEtl.getAttribute(ATT_VALUE));
        }
    }

    private void parseContentTypeOptionsElement(Element element, Map<String, String> headers) {
        Element contentTypeElt = DomUtils.getChildElementByTagName(element, CONTENT_TYPE_ELEMENT);
        if (contentTypeElt != null) {
            headers.put(CONTENT_TYPE_OPTIONS_HEADER, "nosniff");
        }
    }

    private void parseFrameOptionsElement(Element element, ParserContext parserContext, Map<String, String> headers) {
        Element frameElt = DomUtils.getChildElementByTagName(element, FRAME_OPTIONS_ELEMENT);
        if (frameElt != null) {
            String header = getAttribute(frameElt, ATT_POLICY, "DENY");
            if (ALLOW_FROM.equals(header) ) {
                String origin = frameElt.getAttribute(ATT_ORIGIN);
                if (!StringUtils.hasText(origin) ) {
                    parserContext.getReaderContext().error("Frame options header value ALLOW-FROM required an origin to be specified.", frameElt);
                }
                header += " " + origin;
            }
            headers.put(FRAME_OPTIONS_HEADER, header);
        }
    }

    private void parseXssElement(Element element, Map<String, String> headers) {
        Element xssElt = DomUtils.getChildElementByTagName(element, XSS_ELEMENT);
        if (xssElt != null) {
            boolean enabled = Boolean.valueOf(getAttribute(xssElt, ATT_ENABLED, "true"));
            boolean block = Boolean.valueOf(getAttribute(xssElt, ATT_BLOCK, "true"));

            String value = enabled ? "1" : "0";
            if (enabled && block) {
                value += "; mode=block";
            }
            headers.put(XSS_PROTECTION_HEADER, value);
        }
    }

    private String getAttribute(Element element, String name, String defaultValue) {
        String value = element.getAttribute(name);
        if (StringUtils.hasText(value)) {
            return value;
        } else {
            return defaultValue;
        }
    }
}
