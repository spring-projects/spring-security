/*
 * Copyright 2002-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.header.writers.ContentSecurityPolicyHeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginEmbedderPolicyHeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginResourcePolicyHeaderWriter;
import org.springframework.security.web.header.writers.FeaturePolicyHeaderWriter;
import org.springframework.security.web.header.writers.HpkpHeaderWriter;
import org.springframework.security.web.header.writers.HstsHeaderWriter;
import org.springframework.security.web.header.writers.PermissionsPolicyHeaderWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.header.writers.XContentTypeOptionsHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.RegExpAllowFromStrategy;
import org.springframework.security.web.header.writers.frameoptions.StaticAllowFromStrategy;
import org.springframework.security.web.header.writers.frameoptions.WhiteListedAllowFromStrategy;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;

/**
 * Parser for the {@code HeadersFilter}.
 *
 * @author Marten Deinum
 * @author Tim Ysewyn
 * @author Eddú Meléndez
 * @author Vedran Pavic
 * @author Rafiullah Hamedy
 * @since 3.2
 */
public class HeadersBeanDefinitionParser implements BeanDefinitionParser {

	private static final String ATT_DISABLED = "disabled";

	private static final String ATT_POLICY = "policy";

	private static final String ATT_STRATEGY = "strategy";

	private static final String ATT_FROM_PARAMETER = "from-parameter";

	private static final String ATT_NAME = "name";

	private static final String ATT_VALUE = "value";

	private static final String ATT_REF = "ref";

	private static final String ATT_INCLUDE_SUBDOMAINS = "include-subdomains";

	private static final String ATT_MAX_AGE_SECONDS = "max-age-seconds";

	private static final String ATT_REQUEST_MATCHER_REF = "request-matcher-ref";

	private static final String ATT_PRELOAD = "preload";

	private static final String ATT_REPORT_ONLY = "report-only";

	private static final String ATT_REPORT_URI = "report-uri";

	private static final String ATT_ALGORITHM = "algorithm";

	private static final String ATT_POLICY_DIRECTIVES = "policy-directives";

	private static final String ATT_HEADER_VALUE = "header-value";

	private static final String CACHE_CONTROL_ELEMENT = "cache-control";

	private static final String HPKP_ELEMENT = "hpkp";

	private static final String PINS_ELEMENT = "pins";

	private static final String HSTS_ELEMENT = "hsts";

	private static final String XSS_ELEMENT = "xss-protection";

	private static final String CONTENT_TYPE_ELEMENT = "content-type-options";

	private static final String FRAME_OPTIONS_ELEMENT = "frame-options";

	private static final String GENERIC_HEADER_ELEMENT = "header";

	private static final String CONTENT_SECURITY_POLICY_ELEMENT = "content-security-policy";

	private static final String REFERRER_POLICY_ELEMENT = "referrer-policy";

	private static final String FEATURE_POLICY_ELEMENT = "feature-policy";

	private static final String PERMISSIONS_POLICY_ELEMENT = "permissions-policy";

	private static final String CROSS_ORIGIN_OPENER_POLICY_ELEMENT = "cross-origin-opener-policy";

	private static final String CROSS_ORIGIN_EMBEDDER_POLICY_ELEMENT = "cross-origin-embedder-policy";

	private static final String CROSS_ORIGIN_RESOURCE_POLICY_ELEMENT = "cross-origin-resource-policy";

	private static final String ALLOW_FROM = "ALLOW-FROM";

	private ManagedList<BeanMetadataElement> headerWriters;

	@Override
	public BeanDefinition parse(Element element, ParserContext parserContext) {
		this.headerWriters = new ManagedList<>();
		BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(HeaderWriterFilter.class);
		boolean disabled = element != null && "true".equals(resolveAttribute(parserContext, element, "disabled"));
		boolean defaultsDisabled = element != null
				&& "true".equals(resolveAttribute(parserContext, element, "defaults-disabled"));
		boolean addIfNotPresent = element == null || !disabled && !defaultsDisabled;
		parseCacheControlElement(addIfNotPresent, element);
		parseHstsElement(addIfNotPresent, element, parserContext);
		parseXssElement(addIfNotPresent, element, parserContext);
		parseFrameOptionsElement(addIfNotPresent, element, parserContext);
		parseContentTypeOptionsElement(addIfNotPresent, element);
		parseHpkpElement(element == null || !disabled, element, parserContext);
		parseContentSecurityPolicyElement(disabled, element, parserContext);
		parseReferrerPolicyElement(element, parserContext);
		parseFeaturePolicyElement(element, parserContext);
		parsePermissionsPolicyElement(element, parserContext);
		parseCrossOriginOpenerPolicy(disabled, element);
		parseCrossOriginEmbedderPolicy(disabled, element);
		parseCrossOriginResourcePolicy(disabled, element);
		parseHeaderElements(element);
		boolean noWriters = this.headerWriters.isEmpty();
		if (disabled && !noWriters) {
			parserContext.getReaderContext().error("Cannot specify <headers disabled=\"true\"> with child elements.",
					element);
		}
		else if (noWriters) {
			return null;
		}
		builder.addConstructorArgValue(this.headerWriters);
		return builder.getBeanDefinition();
	}

	/**
	 * Resolve the placeholder for a given attribute on a element.
	 * @param pc
	 * @param element
	 * @param attributeName
	 * @return Resolved value of the placeholder
	 */
	private String resolveAttribute(ParserContext pc, Element element, String attributeName) {
		return pc.getReaderContext().getEnvironment().resolvePlaceholders(element.getAttribute(attributeName));
	}

	private void parseCacheControlElement(boolean addIfNotPresent, Element element) {
		Element cacheControlElement = (element != null)
				? DomUtils.getChildElementByTagName(element, CACHE_CONTROL_ELEMENT) : null;
		boolean disabled = "true".equals(getAttribute(cacheControlElement, ATT_DISABLED, "false"));
		if (disabled) {
			return;
		}
		if (addIfNotPresent || cacheControlElement != null) {
			addCacheControl();
		}
	}

	private void addCacheControl() {
		BeanDefinitionBuilder headersWriter = BeanDefinitionBuilder
				.genericBeanDefinition(CacheControlHeadersWriter.class);
		this.headerWriters.add(headersWriter.getBeanDefinition());
	}

	private void parseHstsElement(boolean addIfNotPresent, Element element, ParserContext context) {
		Element hstsElement = (element != null) ? DomUtils.getChildElementByTagName(element, HSTS_ELEMENT) : null;
		if (addIfNotPresent || hstsElement != null) {
			addHsts(addIfNotPresent, hstsElement, context);
		}
	}

	private void addHsts(boolean addIfNotPresent, Element hstsElement, ParserContext context) {
		BeanDefinitionBuilder headersWriter = BeanDefinitionBuilder.genericBeanDefinition(HstsHeaderWriter.class);
		if (hstsElement != null) {
			boolean disabled = "true".equals(getAttribute(hstsElement, ATT_DISABLED, "false"));
			String includeSubDomains = hstsElement.getAttribute(ATT_INCLUDE_SUBDOMAINS);
			if (StringUtils.hasText(includeSubDomains)) {
				if (disabled) {
					attrNotAllowed(context, ATT_INCLUDE_SUBDOMAINS, ATT_DISABLED, hstsElement);
				}
				headersWriter.addPropertyValue("includeSubDomains", includeSubDomains);
			}
			String maxAgeSeconds = hstsElement.getAttribute(ATT_MAX_AGE_SECONDS);
			if (StringUtils.hasText(maxAgeSeconds)) {
				if (disabled) {
					attrNotAllowed(context, ATT_MAX_AGE_SECONDS, ATT_DISABLED, hstsElement);
				}
				headersWriter.addPropertyValue("maxAgeInSeconds", maxAgeSeconds);
			}
			String requestMatcherRef = hstsElement.getAttribute(ATT_REQUEST_MATCHER_REF);
			if (StringUtils.hasText(requestMatcherRef)) {
				if (disabled) {
					attrNotAllowed(context, ATT_REQUEST_MATCHER_REF, ATT_DISABLED, hstsElement);
				}
				headersWriter.addPropertyReference("requestMatcher", requestMatcherRef);
			}
			String preload = hstsElement.getAttribute(ATT_PRELOAD);
			if (StringUtils.hasText(preload)) {
				if (disabled) {
					attrNotAllowed(context, ATT_PRELOAD, ATT_DISABLED, hstsElement);
				}
				headersWriter.addPropertyValue("preload", preload);
			}
			if (disabled) {
				return;
			}
		}
		if (addIfNotPresent || hstsElement != null) {
			this.headerWriters.add(headersWriter.getBeanDefinition());
		}
	}

	private void parseHpkpElement(boolean addIfNotPresent, Element element, ParserContext context) {
		Element hpkpElement = (element != null) ? DomUtils.getChildElementByTagName(element, HPKP_ELEMENT) : null;
		if (addIfNotPresent || hpkpElement != null) {
			addHpkp(addIfNotPresent, hpkpElement, context);
		}
	}

	private void addHpkp(boolean addIfNotPresent, Element hpkpElement, ParserContext context) {
		if (hpkpElement != null) {
			boolean disabled = "true".equals(getAttribute(hpkpElement, ATT_DISABLED, "false"));
			if (disabled) {
				return;
			}
			BeanDefinitionBuilder headersWriter = BeanDefinitionBuilder.genericBeanDefinition(HpkpHeaderWriter.class);
			Element pinsElement = DomUtils.getChildElementByTagName(hpkpElement, PINS_ELEMENT);
			if (pinsElement != null) {
				List<Element> pinElements = DomUtils.getChildElements(pinsElement);
				Map<String, String> pins = new LinkedHashMap<>();
				for (Element pinElement : pinElements) {
					String hash = pinElement.getAttribute(ATT_ALGORITHM);
					if (!StringUtils.hasText(hash)) {
						hash = "sha256";
					}
					Node pinValueNode = pinElement.getFirstChild();
					if (pinValueNode == null) {
						context.getReaderContext().warning("Missing value for pin entry.", hpkpElement);
						continue;
					}
					String fingerprint = pinElement.getFirstChild().getTextContent();
					pins.put(fingerprint, hash);
				}
				headersWriter.addPropertyValue("pins", pins);
			}
			String includeSubDomains = hpkpElement.getAttribute(ATT_INCLUDE_SUBDOMAINS);
			if (StringUtils.hasText(includeSubDomains)) {
				headersWriter.addPropertyValue("includeSubDomains", includeSubDomains);
			}
			String maxAgeSeconds = hpkpElement.getAttribute(ATT_MAX_AGE_SECONDS);
			if (StringUtils.hasText(maxAgeSeconds)) {
				headersWriter.addPropertyValue("maxAgeInSeconds", maxAgeSeconds);
			}
			String reportOnly = hpkpElement.getAttribute(ATT_REPORT_ONLY);
			if (StringUtils.hasText(reportOnly)) {
				headersWriter.addPropertyValue("reportOnly", reportOnly);
			}
			String reportUri = hpkpElement.getAttribute(ATT_REPORT_URI);
			if (StringUtils.hasText(reportUri)) {
				headersWriter.addPropertyValue("reportUri", reportUri);
			}
			if (addIfNotPresent) {
				this.headerWriters.add(headersWriter.getBeanDefinition());
			}
		}
	}

	private void parseContentSecurityPolicyElement(boolean elementDisabled, Element element, ParserContext context) {
		Element contentSecurityPolicyElement = (elementDisabled || element == null) ? null
				: DomUtils.getChildElementByTagName(element, CONTENT_SECURITY_POLICY_ELEMENT);
		if (contentSecurityPolicyElement != null) {
			addContentSecurityPolicy(contentSecurityPolicyElement, context);
		}
	}

	private void addContentSecurityPolicy(Element contentSecurityPolicyElement, ParserContext context) {
		BeanDefinitionBuilder headersWriter = BeanDefinitionBuilder
				.genericBeanDefinition(ContentSecurityPolicyHeaderWriter.class);
		String policyDirectives = contentSecurityPolicyElement.getAttribute(ATT_POLICY_DIRECTIVES);
		if (!StringUtils.hasText(policyDirectives)) {
			context.getReaderContext().error(ATT_POLICY_DIRECTIVES + " requires a 'value' to be set.",
					contentSecurityPolicyElement);
		}
		else {
			headersWriter.addConstructorArgValue(policyDirectives);
		}
		String reportOnly = contentSecurityPolicyElement.getAttribute(ATT_REPORT_ONLY);
		if (StringUtils.hasText(reportOnly)) {
			headersWriter.addPropertyValue("reportOnly", reportOnly);
		}
		this.headerWriters.add(headersWriter.getBeanDefinition());
	}

	private void parseReferrerPolicyElement(Element element, ParserContext context) {
		Element referrerPolicyElement = (element != null)
				? DomUtils.getChildElementByTagName(element, REFERRER_POLICY_ELEMENT) : null;
		if (referrerPolicyElement != null) {
			addReferrerPolicy(referrerPolicyElement, context);
		}
	}

	private void addReferrerPolicy(Element referrerPolicyElement, ParserContext context) {
		BeanDefinitionBuilder headersWriter = BeanDefinitionBuilder
				.genericBeanDefinition(ReferrerPolicyHeaderWriter.class);
		String policy = referrerPolicyElement.getAttribute(ATT_POLICY);
		if (StringUtils.hasLength(policy)) {
			headersWriter.addConstructorArgValue(ReferrerPolicy.get(policy));
		}
		this.headerWriters.add(headersWriter.getBeanDefinition());
	}

	private void parseFeaturePolicyElement(Element element, ParserContext context) {
		Element featurePolicyElement = (element != null)
				? DomUtils.getChildElementByTagName(element, FEATURE_POLICY_ELEMENT) : null;
		if (featurePolicyElement != null) {
			addFeaturePolicy(featurePolicyElement, context);
		}
	}

	private void addFeaturePolicy(Element featurePolicyElement, ParserContext context) {
		BeanDefinitionBuilder headersWriter = BeanDefinitionBuilder
				.genericBeanDefinition(FeaturePolicyHeaderWriter.class);
		String policyDirectives = featurePolicyElement.getAttribute(ATT_POLICY_DIRECTIVES);
		if (!StringUtils.hasText(policyDirectives)) {
			context.getReaderContext().error(ATT_POLICY_DIRECTIVES + " requires a 'value' to be set.",
					featurePolicyElement);
		}
		else {
			headersWriter.addConstructorArgValue(policyDirectives);
		}
		this.headerWriters.add(headersWriter.getBeanDefinition());
	}

	private void parsePermissionsPolicyElement(Element element, ParserContext context) {
		Element permissionsPolicyElement = (element != null)
				? DomUtils.getChildElementByTagName(element, PERMISSIONS_POLICY_ELEMENT) : null;
		if (permissionsPolicyElement != null) {
			addPermissionsPolicy(permissionsPolicyElement, context);
		}
	}

	private void addPermissionsPolicy(Element permissionsPolicyElement, ParserContext context) {
		BeanDefinitionBuilder headersWriter = BeanDefinitionBuilder
				.genericBeanDefinition(PermissionsPolicyHeaderWriter.class);
		String policyDirectives = permissionsPolicyElement.getAttribute(ATT_POLICY);
		if (!StringUtils.hasText(policyDirectives)) {
			context.getReaderContext().error(ATT_POLICY + " requires a 'value' to be set.", permissionsPolicyElement);
		}
		else {
			headersWriter.addConstructorArgValue(policyDirectives);
		}
		this.headerWriters.add(headersWriter.getBeanDefinition());
	}

	private void parseCrossOriginOpenerPolicy(boolean elementDisabled, Element element) {
		if (elementDisabled || element == null) {
			return;
		}
		CrossOriginOpenerPolicyHeaderWriter writer = new CrossOriginOpenerPolicyHeaderWriter();
		Element crossOriginOpenerPolicyElement = DomUtils.getChildElementByTagName(element,
				CROSS_ORIGIN_OPENER_POLICY_ELEMENT);
		if (crossOriginOpenerPolicyElement != null) {
			addCrossOriginOpenerPolicy(crossOriginOpenerPolicyElement, writer);
		}
		BeanDefinitionBuilder builder = BeanDefinitionBuilder
				.genericBeanDefinition(CrossOriginOpenerPolicyHeaderWriter.class, () -> writer);
		this.headerWriters.add(builder.getBeanDefinition());
	}

	private void parseCrossOriginEmbedderPolicy(boolean elementDisabled, Element element) {
		if (elementDisabled || element == null) {
			return;
		}
		CrossOriginEmbedderPolicyHeaderWriter writer = new CrossOriginEmbedderPolicyHeaderWriter();
		Element crossOriginEmbedderPolicyElement = DomUtils.getChildElementByTagName(element,
				CROSS_ORIGIN_EMBEDDER_POLICY_ELEMENT);
		if (crossOriginEmbedderPolicyElement != null) {
			addCrossOriginEmbedderPolicy(crossOriginEmbedderPolicyElement, writer);
		}
		BeanDefinitionBuilder builder = BeanDefinitionBuilder
				.genericBeanDefinition(CrossOriginEmbedderPolicyHeaderWriter.class, () -> writer);
		this.headerWriters.add(builder.getBeanDefinition());
	}

	private void parseCrossOriginResourcePolicy(boolean elementDisabled, Element element) {
		if (elementDisabled || element == null) {
			return;
		}
		CrossOriginResourcePolicyHeaderWriter writer = new CrossOriginResourcePolicyHeaderWriter();
		Element crossOriginResourcePolicyElement = DomUtils.getChildElementByTagName(element,
				CROSS_ORIGIN_RESOURCE_POLICY_ELEMENT);
		if (crossOriginResourcePolicyElement != null) {
			addCrossOriginResourcePolicy(crossOriginResourcePolicyElement, writer);
		}
		BeanDefinitionBuilder builder = BeanDefinitionBuilder
				.genericBeanDefinition(CrossOriginResourcePolicyHeaderWriter.class, () -> writer);
		this.headerWriters.add(builder.getBeanDefinition());
	}

	private void addCrossOriginResourcePolicy(Element crossOriginResourcePolicyElement,
			CrossOriginResourcePolicyHeaderWriter writer) {
		String policy = crossOriginResourcePolicyElement.getAttribute(ATT_POLICY);
		if (StringUtils.hasText(policy)) {
			writer.setPolicy(CrossOriginResourcePolicyHeaderWriter.CrossOriginResourcePolicy.from(policy));
		}
	}

	private void addCrossOriginEmbedderPolicy(Element crossOriginEmbedderPolicyElement,
			CrossOriginEmbedderPolicyHeaderWriter writer) {
		String policy = crossOriginEmbedderPolicyElement.getAttribute(ATT_POLICY);
		if (StringUtils.hasText(policy)) {
			writer.setPolicy(CrossOriginEmbedderPolicyHeaderWriter.CrossOriginEmbedderPolicy.from(policy));
		}
	}

	private void addCrossOriginOpenerPolicy(Element crossOriginOpenerPolicyElement,
			CrossOriginOpenerPolicyHeaderWriter writer) {
		String policy = crossOriginOpenerPolicyElement.getAttribute(ATT_POLICY);
		if (StringUtils.hasText(policy)) {
			writer.setPolicy(CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy.from(policy));
		}
	}

	private void attrNotAllowed(ParserContext context, String attrName, String otherAttrName, Element element) {
		context.getReaderContext().error("Only one of '" + attrName + "' or '" + otherAttrName + "' can be set.",
				element);
	}

	private void parseHeaderElements(Element element) {
		List<Element> headerElts = (element != null)
				? DomUtils.getChildElementsByTagName(element, GENERIC_HEADER_ELEMENT) : Collections.emptyList();
		for (Element headerElt : headerElts) {
			String headerFactoryRef = headerElt.getAttribute(ATT_REF);
			if (StringUtils.hasText(headerFactoryRef)) {
				this.headerWriters.add(new RuntimeBeanReference(headerFactoryRef));
			}
			else {
				BeanDefinitionBuilder builder = BeanDefinitionBuilder.genericBeanDefinition(StaticHeadersWriter.class);
				builder.addConstructorArgValue(headerElt.getAttribute(ATT_NAME));
				builder.addConstructorArgValue(headerElt.getAttribute(ATT_VALUE));
				this.headerWriters.add(builder.getBeanDefinition());
			}
		}
	}

	private void parseContentTypeOptionsElement(boolean addIfNotPresent, Element element) {
		Element contentTypeElt = (element != null) ? DomUtils.getChildElementByTagName(element, CONTENT_TYPE_ELEMENT)
				: null;
		boolean disabled = "true".equals(getAttribute(contentTypeElt, ATT_DISABLED, "false"));
		if (disabled) {
			return;
		}
		if (addIfNotPresent || contentTypeElt != null) {
			addContentTypeOptions();
		}
	}

	private void addContentTypeOptions() {
		BeanDefinitionBuilder builder = BeanDefinitionBuilder
				.genericBeanDefinition(XContentTypeOptionsHeaderWriter.class);
		this.headerWriters.add(builder.getBeanDefinition());
	}

	private void parseFrameOptionsElement(boolean addIfNotPresent, Element element, ParserContext parserContext) {
		BeanDefinitionBuilder builder = BeanDefinitionBuilder.genericBeanDefinition(XFrameOptionsHeaderWriter.class);
		Element frameElement = (element != null) ? DomUtils.getChildElementByTagName(element, FRAME_OPTIONS_ELEMENT)
				: null;
		if (frameElement == null) {
			if (addIfNotPresent) {
				this.headerWriters.add(builder.getBeanDefinition());
			}
			return;
		}
		String header = getAttribute(frameElement, ATT_POLICY, null);
		boolean disabled = "true".equals(getAttribute(frameElement, ATT_DISABLED, "false"));
		if (disabled && header != null) {
			this.attrNotAllowed(parserContext, ATT_DISABLED, ATT_POLICY, frameElement);
		}
		header = StringUtils.hasText(header) ? header : "DENY";
		if (ALLOW_FROM.equals(header)) {
			parseAllowFromFrameOptionsElement(parserContext, builder, frameElement);
		}
		else {
			builder.addConstructorArgValue(header);
		}
		if (!disabled) {
			this.headerWriters.add(builder.getBeanDefinition());
		}
	}

	private void parseAllowFromFrameOptionsElement(ParserContext parserContext, BeanDefinitionBuilder builder,
			Element frameElement) {
		String strategyRef = getAttribute(frameElement, ATT_REF, null);
		String strategy = getAttribute(frameElement, ATT_STRATEGY, null);
		if (StringUtils.hasText(strategy) && StringUtils.hasText(strategyRef)) {
			parserContext.getReaderContext().error("Only one of 'strategy' or 'strategy-ref' can be set.",
					frameElement);
			return;
		}
		if (strategyRef != null) {
			builder.addConstructorArgReference(strategyRef);
			return;
		}
		if (strategy == null) {
			parserContext.getReaderContext().error("One of 'strategy' and 'strategy-ref' must be set.", frameElement);
			return;
		}
		String value = getAttribute(frameElement, ATT_VALUE, null);
		if (!StringUtils.hasText(value)) {
			parserContext.getReaderContext().error("Strategy requires a 'value' to be set.", frameElement);
			return;
		}
		// static, whitelist, regexp
		if ("static".equals(strategy)) {
			try {
				builder.addConstructorArgValue(new StaticAllowFromStrategy(new URI(value)));
			}
			catch (URISyntaxException ex) {
				parserContext.getReaderContext().error("'value' attribute doesn't represent a valid URI.", frameElement,
						ex);
			}
			return;
		}
		BeanDefinitionBuilder allowFromStrategy = getAllowFromStrategy(strategy, value);
		String fromParameter = getAttribute(frameElement, ATT_FROM_PARAMETER, "from");
		allowFromStrategy.addPropertyValue("allowFromParameterName", fromParameter);
		builder.addConstructorArgValue(allowFromStrategy.getBeanDefinition());
	}

	private BeanDefinitionBuilder getAllowFromStrategy(String strategy, String value) {
		if ("whitelist".equals(strategy)) {
			BeanDefinitionBuilder allowFromStrategy = BeanDefinitionBuilder
					.rootBeanDefinition(WhiteListedAllowFromStrategy.class);
			allowFromStrategy.addConstructorArgValue(StringUtils.commaDelimitedListToSet(value));
			return allowFromStrategy;
		}
		BeanDefinitionBuilder allowFromStrategy;
		allowFromStrategy = BeanDefinitionBuilder.rootBeanDefinition(RegExpAllowFromStrategy.class);
		allowFromStrategy.addConstructorArgValue(value);
		return allowFromStrategy;
	}

	private void parseXssElement(boolean addIfNotPresent, Element element, ParserContext parserContext) {
		Element xssElt = (element != null) ? DomUtils.getChildElementByTagName(element, XSS_ELEMENT) : null;
		BeanDefinitionBuilder builder = BeanDefinitionBuilder.genericBeanDefinition(XXssProtectionHeaderWriter.class);
		if (xssElt != null) {
			boolean disabled = "true".equals(getAttribute(xssElt, ATT_DISABLED, "false"));
			XXssProtectionHeaderWriter.HeaderValue headerValue = XXssProtectionHeaderWriter.HeaderValue
					.from(xssElt.getAttribute(ATT_HEADER_VALUE));
			if (headerValue != null) {
				if (disabled) {
					attrNotAllowed(parserContext, ATT_HEADER_VALUE, ATT_DISABLED, xssElt);
				}
				builder.addPropertyValue("headerValue", headerValue);
			}
			if (disabled) {
				return;
			}
		}
		if (addIfNotPresent || xssElt != null) {
			this.headerWriters.add(builder.getBeanDefinition());
		}
	}

	private String getAttribute(Element element, String name, String defaultValue) {
		if (element == null) {
			return defaultValue;
		}
		String value = element.getAttribute(name);
		if (StringUtils.hasText(value)) {
			return value;
		}
		return defaultValue;
	}

}
