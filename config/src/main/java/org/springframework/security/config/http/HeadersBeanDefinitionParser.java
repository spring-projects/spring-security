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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.regex.PatternSyntaxException;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.header.writers.HstsHeaderWriter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.header.writers.XContentTypeOptionsHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.AbstractRequestParameterAllowFromStrategy;
import org.springframework.security.web.header.writers.frameoptions.RegExpAllowFromStrategy;
import org.springframework.security.web.header.writers.frameoptions.StaticAllowFromStrategy;
import org.springframework.security.web.header.writers.frameoptions.WhiteListedAllowFromStrategy;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

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
    private static final String ATT_STRATEGY = "strategy";
    private static final String ATT_FROM_PARAMETER = "from-parameter";

    private static final String ATT_NAME = "name";
    private static final String ATT_VALUE = "value";
    private static final String ATT_REF = "ref";

    private static final String ATT_INCLUDE_SUBDOMAINS = "include-subdomains";
    private static final String ATT_MAX_AGE_SECONDS = "max-age-seconds";
    private static final String ATT_REQUEST_MATCHER_REF = "request-matcher-ref";

    private static final String CACHE_CONTROL_ELEMENT = "cache-control";

    private static final String HSTS_ELEMENT = "hsts";

    private static final String XSS_ELEMENT = "xss-protection";
    private static final String CONTENT_TYPE_ELEMENT = "content-type-options";
    private static final String FRAME_OPTIONS_ELEMENT = "frame-options";
    private static final String GENERIC_HEADER_ELEMENT = "header";

    private static final String ALLOW_FROM = "ALLOW-FROM";

    private ManagedList<BeanMetadataElement> headerWriters;

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        headerWriters = new ManagedList<BeanMetadataElement>();
        BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(HeaderWriterFilter.class);

        parseCacheControlElement(element);
        parseHstsElement(element);
        parseXssElement(element, parserContext);
        parseFrameOptionsElement(element, parserContext);
        parseContentTypeOptionsElement(element);

        parseHeaderElements(element);

        if(headerWriters.isEmpty()) {
            addCacheControl();
            addHsts(null);
            addContentTypeOptions();

            BeanDefinitionBuilder frameOptions = BeanDefinitionBuilder.genericBeanDefinition(XFrameOptionsHeaderWriter.class);
            frameOptions.addConstructorArgValue("DENY");
            headerWriters.add(frameOptions.getBeanDefinition());

            BeanDefinitionBuilder xss = BeanDefinitionBuilder.genericBeanDefinition(XXssProtectionHeaderWriter.class);
            headerWriters.add(xss.getBeanDefinition());
        }
        builder.addConstructorArgValue(headerWriters);
        return builder.getBeanDefinition();
    }

    private void parseCacheControlElement(Element element) {
        Element cacheControlElement = DomUtils.getChildElementByTagName(element, CACHE_CONTROL_ELEMENT);
        if (cacheControlElement != null) {
            addCacheControl();
        }
    }

    private void addCacheControl() {
        BeanDefinitionBuilder headersWriter = BeanDefinitionBuilder.genericBeanDefinition(CacheControlHeadersWriter.class);
        headerWriters.add(headersWriter.getBeanDefinition());
    }

    private void parseHstsElement(Element element) {
        Element hstsElement = DomUtils.getChildElementByTagName(element, HSTS_ELEMENT);
        if (hstsElement != null) {
            addHsts(hstsElement);
        }
    }

    private void addHsts(Element hstsElement) {
        BeanDefinitionBuilder headersWriter = BeanDefinitionBuilder.genericBeanDefinition(HstsHeaderWriter.class);
        if(hstsElement != null) {
            String includeSubDomains = hstsElement.getAttribute(ATT_INCLUDE_SUBDOMAINS);
            if(StringUtils.hasText(includeSubDomains)) {
                headersWriter.addPropertyValue("includeSubDomains", includeSubDomains);
            }
            String maxAgeSeconds = hstsElement.getAttribute(ATT_MAX_AGE_SECONDS);
            if(StringUtils.hasText(maxAgeSeconds)) {
                headersWriter.addPropertyValue("maxAgeInSeconds", maxAgeSeconds);
            }
            String requestMatcherRef = hstsElement.getAttribute(ATT_REQUEST_MATCHER_REF);
            if(StringUtils.hasText(requestMatcherRef)) {
                headersWriter.addPropertyReference("requestMatcher", requestMatcherRef);
            }
        }
        headerWriters.add(headersWriter.getBeanDefinition());
    }

    private void parseHeaderElements(Element element) {
        List<Element> headerElts = DomUtils.getChildElementsByTagName(element, GENERIC_HEADER_ELEMENT);
        for (Element headerElt : headerElts) {
            String headerFactoryRef = headerElt.getAttribute(ATT_REF);
            if (StringUtils.hasText(headerFactoryRef)) {
                headerWriters.add(new RuntimeBeanReference(headerFactoryRef));
            } else {
                BeanDefinitionBuilder builder = BeanDefinitionBuilder.genericBeanDefinition(StaticHeadersWriter.class);
                builder.addConstructorArgValue(headerElt.getAttribute(ATT_NAME));
                builder.addConstructorArgValue(headerElt.getAttribute(ATT_VALUE));
                headerWriters.add(builder.getBeanDefinition());
            }
        }
    }

    private void parseContentTypeOptionsElement(Element element) {
        Element contentTypeElt = DomUtils.getChildElementByTagName(element, CONTENT_TYPE_ELEMENT);
        if (contentTypeElt != null) {
            addContentTypeOptions();
        }
    }

    private void addContentTypeOptions() {
        BeanDefinitionBuilder builder = BeanDefinitionBuilder.genericBeanDefinition(XContentTypeOptionsHeaderWriter.class);
        headerWriters.add(builder.getBeanDefinition());
    }

    private void parseFrameOptionsElement(Element element, ParserContext parserContext) {
        BeanDefinitionBuilder builder = BeanDefinitionBuilder.genericBeanDefinition(XFrameOptionsHeaderWriter.class);

        Element frameElt = DomUtils.getChildElementByTagName(element, FRAME_OPTIONS_ELEMENT);
        if (frameElt != null) {
            String header = getAttribute(frameElt, ATT_POLICY, "DENY");
            if (ALLOW_FROM.equals(header) ) {
                String strategyRef = getAttribute(frameElt, ATT_REF, null);
                String strategy = getAttribute(frameElt, ATT_STRATEGY, null);

                if (StringUtils.hasText(strategy) && StringUtils.hasText(strategyRef)) {
                    parserContext.getReaderContext().error("Only one of 'strategy' or 'strategy-ref' can be set.",
                            frameElt);
                } else if (strategyRef != null) {
                    builder.addConstructorArgReference(strategyRef);
                } else if (strategy != null) {
                    String value = getAttribute(frameElt, ATT_VALUE, null);
                    if (!StringUtils.hasText(value)) {
                        parserContext.getReaderContext().error("Strategy requires a 'value' to be set.", frameElt);
                    }
                    // static, whitelist, regexp
                    if ("static".equals(strategy)) {
                        try {
                            builder.addConstructorArgValue(new StaticAllowFromStrategy(new URI(value)));
                        } catch (URISyntaxException e) {
                            parserContext.getReaderContext().error(
                                    "'value' attribute doesn't represent a valid URI.", frameElt, e);
                        }
                    } else {
                        AbstractRequestParameterAllowFromStrategy allowFromStrategy = null;
                        if ("whitelist".equals(strategy)) {
                            allowFromStrategy = new WhiteListedAllowFromStrategy(
                                    StringUtils.commaDelimitedListToSet(value));
                        } else {
                            try {
                                allowFromStrategy = new RegExpAllowFromStrategy(value);
                            } catch (PatternSyntaxException e) {
                                parserContext.getReaderContext().error(
                                        "'value' attribute doesn't represent a valid regular expression.", frameElt, e);
                            }
                        }
                        String fromParameter = getAttribute(frameElt, ATT_FROM_PARAMETER, "from");
                        allowFromStrategy.setAllowFromParameterName(fromParameter);
                        builder.addConstructorArgValue(allowFromStrategy);
                    }
                } else {
                    parserContext.getReaderContext().error("One of 'strategy' and 'strategy-ref' must be set.",
                            frameElt);
                }
            } else {
                builder.addConstructorArgValue(header);
            }
            headerWriters.add(builder.getBeanDefinition());
        }
    }

    private void parseXssElement(Element element, ParserContext parserContext) {
        Element xssElt = DomUtils.getChildElementByTagName(element, XSS_ELEMENT);
        if (xssElt != null) {
            String enabled = xssElt.getAttribute(ATT_ENABLED);
            String block = xssElt.getAttribute(ATT_BLOCK);

            BeanDefinitionBuilder builder = BeanDefinitionBuilder.genericBeanDefinition(XXssProtectionHeaderWriter.class);
            if(StringUtils.hasText(enabled)) {
                builder.addPropertyValue("enabled", enabled);
            }
            if(StringUtils.hasText(block)) {
                builder.addPropertyValue("block", block);
            }
            headerWriters.add(builder.getBeanDefinition());
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
