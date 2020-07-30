/*
 * Copyright 2009-2020 the original author or authors.
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

package org.springframework.security.config;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.xml.BeanDefinitionDecorator;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.NamespaceHandler;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.authentication.AuthenticationManagerBeanDefinitionParser;
import org.springframework.security.config.authentication.AuthenticationProviderBeanDefinitionParser;
import org.springframework.security.config.authentication.JdbcUserServiceBeanDefinitionParser;
import org.springframework.security.config.authentication.UserServiceBeanDefinitionParser;
import org.springframework.security.config.http.FilterChainBeanDefinitionParser;
import org.springframework.security.config.http.FilterChainMapBeanDefinitionDecorator;
import org.springframework.security.config.http.FilterInvocationSecurityMetadataSourceParser;
import org.springframework.security.config.http.HttpFirewallBeanDefinitionParser;
import org.springframework.security.config.http.HttpSecurityBeanDefinitionParser;
import org.springframework.security.config.ldap.LdapProviderBeanDefinitionParser;
import org.springframework.security.config.ldap.LdapServerBeanDefinitionParser;
import org.springframework.security.config.ldap.LdapUserServiceBeanDefinitionParser;
import org.springframework.security.config.method.GlobalMethodSecurityBeanDefinitionParser;
import org.springframework.security.config.method.InterceptMethodsBeanDefinitionDecorator;
import org.springframework.security.config.method.MethodSecurityMetadataSourceBeanDefinitionParser;
import org.springframework.security.config.oauth2.client.ClientRegistrationsBeanDefinitionParser;
import org.springframework.security.config.websocket.WebSocketMessageBrokerSecurityBeanDefinitionParser;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.ClassUtils;

/**
 * Parses elements from the "security" namespace
 * (http://www.springframework.org/schema/security).
 *
 * @author Luke Taylor
 * @author Ben Alex
 * @author Rob Winch
 * @since 2.0
 */
public final class SecurityNamespaceHandler implements NamespaceHandler {

	private static final String FILTER_CHAIN_PROXY_CLASSNAME = "org.springframework.security.web.FilterChainProxy";

	private static final String MESSAGE_CLASSNAME = "org.springframework.messaging.Message";

	private final Log logger = LogFactory.getLog(getClass());

	private final Map<String, BeanDefinitionParser> parsers = new HashMap<>();

	private final BeanDefinitionDecorator interceptMethodsBDD = new InterceptMethodsBeanDefinitionDecorator();

	private BeanDefinitionDecorator filterChainMapBDD;

	public SecurityNamespaceHandler() {
		String coreVersion = SpringSecurityCoreVersion.getVersion();

		Package pkg = SpringSecurityCoreVersion.class.getPackage();

		if (pkg == null || coreVersion == null) {
			this.logger.info("Couldn't determine package version information.");
			return;
		}

		String version = pkg.getImplementationVersion();
		this.logger.info("Spring Security 'config' module version is " + version);

		if (version.compareTo(coreVersion) != 0) {
			this.logger.error(
					"You are running with different versions of the Spring Security 'core' and 'config' modules");
		}
	}

	@Override
	public BeanDefinition parse(Element element, ParserContext pc) {
		if (!namespaceMatchesVersion(element)) {
			pc.getReaderContext().fatal(
					"You cannot use a spring-security-2.0.xsd or spring-security-3.0.xsd or spring-security-3.1.xsd schema or spring-security-3.2.xsd schema or spring-security-4.0.xsd schema "
							+ "with Spring Security 5.4. Please update your schema declarations to the 5.4 schema.",
					element);
		}
		String name = pc.getDelegate().getLocalName(element);
		BeanDefinitionParser parser = this.parsers.get(name);

		if (parser == null) {
			// SEC-1455. Load parsers when required, not just on init().
			loadParsers();
		}

		if (parser == null) {
			if (Elements.HTTP.equals(name) || Elements.FILTER_SECURITY_METADATA_SOURCE.equals(name)
					|| Elements.FILTER_CHAIN_MAP.equals(name) || Elements.FILTER_CHAIN.equals(name)) {
				reportMissingWebClasses(name, pc, element);
			}
			else {
				reportUnsupportedNodeType(name, pc, element);
			}

			return null;
		}

		return parser.parse(element, pc);
	}

	@Override
	public BeanDefinitionHolder decorate(Node node, BeanDefinitionHolder definition, ParserContext pc) {
		String name = pc.getDelegate().getLocalName(node);

		// We only handle elements
		if (node instanceof Element) {
			if (Elements.INTERCEPT_METHODS.equals(name)) {
				return this.interceptMethodsBDD.decorate(node, definition, pc);
			}

			if (Elements.FILTER_CHAIN_MAP.equals(name)) {
				if (this.filterChainMapBDD == null) {
					loadParsers();
				}
				if (this.filterChainMapBDD == null) {
					reportMissingWebClasses(name, pc, node);
				}
				return this.filterChainMapBDD.decorate(node, definition, pc);
			}
		}

		reportUnsupportedNodeType(name, pc, node);

		return null;
	}

	private void reportUnsupportedNodeType(String name, ParserContext pc, Node node) {
		pc.getReaderContext().fatal("Security namespace does not support decoration of "
				+ ((node instanceof Element) ? "element" : "attribute") + " [" + name + "]", node);
	}

	private void reportMissingWebClasses(String nodeName, ParserContext pc, Node node) {
		String errorMessage = "The classes from the spring-security-web jar "
				+ "(or one of its dependencies) are not available. You need these to use <" + nodeName + ">";
		try {
			ClassUtils.forName(FILTER_CHAIN_PROXY_CLASSNAME, getClass().getClassLoader());
			// no details available
			pc.getReaderContext().fatal(errorMessage, node);
		}
		catch (Throwable cause) {
			// provide details on why it could not be loaded
			pc.getReaderContext().fatal(errorMessage, node, cause);
		}
	}

	@Override
	public void init() {
		loadParsers();
	}

	private void loadParsers() {
		// Parsers
		this.parsers.put(Elements.LDAP_PROVIDER, new LdapProviderBeanDefinitionParser());
		this.parsers.put(Elements.LDAP_SERVER, new LdapServerBeanDefinitionParser());
		this.parsers.put(Elements.LDAP_USER_SERVICE, new LdapUserServiceBeanDefinitionParser());
		this.parsers.put(Elements.USER_SERVICE, new UserServiceBeanDefinitionParser());
		this.parsers.put(Elements.JDBC_USER_SERVICE, new JdbcUserServiceBeanDefinitionParser());
		this.parsers.put(Elements.AUTHENTICATION_PROVIDER, new AuthenticationProviderBeanDefinitionParser());
		this.parsers.put(Elements.GLOBAL_METHOD_SECURITY, new GlobalMethodSecurityBeanDefinitionParser());
		this.parsers.put(Elements.AUTHENTICATION_MANAGER, new AuthenticationManagerBeanDefinitionParser());
		this.parsers.put(Elements.METHOD_SECURITY_METADATA_SOURCE,
				new MethodSecurityMetadataSourceBeanDefinitionParser());

		// Only load the web-namespace parsers if the web classes are available
		if (ClassUtils.isPresent(FILTER_CHAIN_PROXY_CLASSNAME, getClass().getClassLoader())) {
			this.parsers.put(Elements.DEBUG, new DebugBeanDefinitionParser());
			this.parsers.put(Elements.HTTP, new HttpSecurityBeanDefinitionParser());
			this.parsers.put(Elements.HTTP_FIREWALL, new HttpFirewallBeanDefinitionParser());
			this.parsers.put(Elements.FILTER_SECURITY_METADATA_SOURCE,
					new FilterInvocationSecurityMetadataSourceParser());
			this.parsers.put(Elements.FILTER_CHAIN, new FilterChainBeanDefinitionParser());
			this.filterChainMapBDD = new FilterChainMapBeanDefinitionDecorator();
			this.parsers.put(Elements.CLIENT_REGISTRATIONS, new ClientRegistrationsBeanDefinitionParser());
		}

		if (ClassUtils.isPresent(MESSAGE_CLASSNAME, getClass().getClassLoader())) {
			this.parsers.put(Elements.WEBSOCKET_MESSAGE_BROKER,
					new WebSocketMessageBrokerSecurityBeanDefinitionParser());
		}
	}

	/**
	 * Check that the schema location declared in the source file being parsed matches the
	 * Spring Security version. The old 2.0 schema is not compatible with the 3.1 parser,
	 * so it is an error to explicitly use 2.0.
	 * <p>
	 * There are also differences between 3.0 and 3.1 which are sufficient that we report
	 * using 3.0 as an error too. It might be an error to declare spring-security.xsd as
	 * an alias, but you are only going to find that out when one of the sub parsers
	 * breaks.
	 * @param element the element that is to be parsed next
	 * @return true if we find a schema declaration that matches
	 */
	private boolean namespaceMatchesVersion(Element element) {
		return matchesVersionInternal(element)
				&& matchesVersionInternal(element.getOwnerDocument().getDocumentElement());
	}

	private boolean matchesVersionInternal(Element element) {
		String schemaLocation = element.getAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "schemaLocation");
		return schemaLocation.matches("(?m).*spring-security-5\\.4.*.xsd.*")
				|| schemaLocation.matches("(?m).*spring-security.xsd.*")
				|| !schemaLocation.matches("(?m).*spring-security.*");
	}

}
