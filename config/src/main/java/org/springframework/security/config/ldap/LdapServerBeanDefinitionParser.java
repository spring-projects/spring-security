/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.config.ldap;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.BeanIds;
import org.springframework.security.ldap.server.ApacheDSContainer;
import org.springframework.security.ldap.server.UnboundIdContainer;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @author Eddú Meléndez
 */
public class LdapServerBeanDefinitionParser implements BeanDefinitionParser {
	private static final String CONTEXT_SOURCE_CLASS = "org.springframework.security.ldap.DefaultSpringSecurityContextSource";

	private final Log logger = LogFactory.getLog(getClass());

	/**
	 * Defines the Url of the ldap server to use. If not specified, an embedded apache DS
	 * instance will be created
	 */
	private static final String ATT_URL = "url";

	private static final String ATT_PRINCIPAL = "manager-dn";
	private static final String ATT_PASSWORD = "manager-password";

	// Properties which apply to embedded server only - when no Url is set

	/** sets the configuration suffix (default is "dc=springframework,dc=org"). */
	public static final String ATT_ROOT_SUFFIX = "root";
	private static final String OPT_DEFAULT_ROOT_SUFFIX = "dc=springframework,dc=org";
	/**
	 * Optionally defines an ldif resource to be loaded. Otherwise an attempt will be made
	 * to load all ldif files found on the classpath.
	 */
	public static final String ATT_LDIF_FILE = "ldif";
	private static final String OPT_DEFAULT_LDIF_FILE = "classpath*:*.ldif";

	/** Defines the port the LDAP_PROVIDER server should run on */
	public static final String ATT_PORT = "port";
	private static final int DEFAULT_PORT = 33389;
	public static final String OPT_DEFAULT_PORT = String.valueOf(DEFAULT_PORT);

	private static final String APACHEDS_CLASSNAME = "org.apache.directory.server.core.DefaultDirectoryService";
	private static final String UNBOUNID_CLASSNAME = "com.unboundid.ldap.listener.InMemoryDirectoryServer";

	private static final String APACHEDS_CONTAINER_CLASSNAME = "org.springframework.security.ldap.server.ApacheDSContainer";
	private static final String UNBOUNDID_CONTAINER_CLASSNAME = "org.springframework.security.ldap.server.UnboundIdContainer";

	private Map<String, EmbeddedLdapServer> embeddedServers;

	public LdapServerBeanDefinitionParser() {
		Map<String, EmbeddedLdapServer> embeddedLdapServers = new HashMap<>();
		embeddedLdapServers.put("apacheds", new EmbeddedLdapServer(BeanIds.EMBEDDED_APACHE_DS, APACHEDS_CLASSNAME, APACHEDS_CONTAINER_CLASSNAME));
		embeddedLdapServers.put("unboundid", new EmbeddedLdapServer(BeanIds.EMBEDDED_UNBOUNDID, UNBOUNID_CLASSNAME, UNBOUNDID_CONTAINER_CLASSNAME));

		this.embeddedServers = Collections.unmodifiableMap(embeddedLdapServers);
	}

	public BeanDefinition parse(Element elt, ParserContext parserContext) {
		String url = elt.getAttribute(ATT_URL);

		RootBeanDefinition contextSource;

		if (!StringUtils.hasText(url)) {
			contextSource = createEmbeddedServer(elt, parserContext);
		}
		else {
			contextSource = new RootBeanDefinition();
			contextSource.setBeanClassName(CONTEXT_SOURCE_CLASS);
			contextSource.getConstructorArgumentValues().addIndexedArgumentValue(0, url);
		}

		contextSource.setSource(parserContext.extractSource(elt));

		String managerDn = elt.getAttribute(ATT_PRINCIPAL);
		String managerPassword = elt.getAttribute(ATT_PASSWORD);

		if (StringUtils.hasText(managerDn)) {
			if (!StringUtils.hasText(managerPassword)) {
				parserContext.getReaderContext().error(
						"You must specify the " + ATT_PASSWORD + " if you supply a "
								+ managerDn, elt);
			}

			contextSource.getPropertyValues().addPropertyValue("userDn", managerDn);
			contextSource.getPropertyValues().addPropertyValue("password",
					managerPassword);
		}

		String id = elt.getAttribute(AbstractBeanDefinitionParser.ID_ATTRIBUTE);

		String contextSourceId = StringUtils.hasText(id) ? id : BeanIds.CONTEXT_SOURCE;

		parserContext.getRegistry()
				.registerBeanDefinition(contextSourceId, contextSource);

		return null;
	}

	/**
	 * Will be called if no url attribute is supplied.
	 *
	 * Registers beans to create an embedded apache directory server.
	 *
	 * @return the BeanDefinition for the ContextSource for the embedded server.
	 *
	 * @see ApacheDSContainer
	 * @see UnboundIdContainer
	 */
	private RootBeanDefinition createEmbeddedServer(Element element,
			ParserContext parserContext) {
		Object source = parserContext.extractSource(element);

		String suffix = element.getAttribute(ATT_ROOT_SUFFIX);

		if (!StringUtils.hasText(suffix)) {
			suffix = OPT_DEFAULT_ROOT_SUFFIX;
		}

		String port = element.getAttribute(ATT_PORT);

		if (!StringUtils.hasText(port)) {
			port = getDefaultPort();
			if (logger.isDebugEnabled()) {
				logger.debug("Using default port of " + port);
			}
		}

		String url = "ldap://127.0.0.1:" + port + "/" + suffix;

		BeanDefinitionBuilder contextSource = BeanDefinitionBuilder
				.rootBeanDefinition(CONTEXT_SOURCE_CLASS);
		contextSource.addConstructorArgValue(url);
		contextSource.addPropertyValue("userDn", "uid=admin,ou=system");
		contextSource.addPropertyValue("password", "secret");

		String mode = element.getAttribute("mode");
		RootBeanDefinition ldapContainer = getRootBeanDefinition(mode);
		ldapContainer.setSource(source);
		ldapContainer.getConstructorArgumentValues().addGenericArgumentValue(suffix);

		String ldifs = element.getAttribute(ATT_LDIF_FILE);
		if (!StringUtils.hasText(ldifs)) {
			ldifs = OPT_DEFAULT_LDIF_FILE;
		}

		ldapContainer.getConstructorArgumentValues().addGenericArgumentValue(ldifs);
		ldapContainer.getPropertyValues().addPropertyValue("port", port);

		logger.info("Embedded LDAP server bean definition created for URL: " + url);

		if (parserContext.getRegistry()
				.containsBeanDefinition(BeanIds.EMBEDDED_APACHE_DS) ||
				parserContext.getRegistry().containsBeanDefinition(BeanIds.EMBEDDED_UNBOUNDID)) {
			parserContext.getReaderContext().error(
					"Only one embedded server bean is allowed per application context",
					element);
		}

		EmbeddedLdapServer embeddedLdapServer = resolveEmbeddedLdapServer(mode);
		if (embeddedLdapServer != null) {
			parserContext.getRegistry().registerBeanDefinition(embeddedLdapServer.getBeanId(),
					ldapContainer);
		}

		return (RootBeanDefinition) contextSource.getBeanDefinition();
	}

	private RootBeanDefinition getRootBeanDefinition(String mode) {
		if (StringUtils.hasLength(mode)) {
			if (isEmbeddedServerEnabled(mode)) {
				return new RootBeanDefinition(this.embeddedServers.get(mode).getContainerClass(), null, null);
			}
		}
		else {
			for (Map.Entry<String, EmbeddedLdapServer> entry : this.embeddedServers.entrySet()) {
				EmbeddedLdapServer ldapServer = entry.getValue();
				if (ClassUtils.isPresent(ldapServer.getClassName(), getClass().getClassLoader())) {
					return new RootBeanDefinition(ldapServer.getContainerClass(), null, null);
				}
			}
		}
		throw new IllegalStateException("Embedded LDAP server is not provided");
	}

	private boolean isEmbeddedServerEnabled(String mode) {
		EmbeddedLdapServer server = resolveEmbeddedLdapServer(mode);
		return server != null;
	}

	private EmbeddedLdapServer resolveEmbeddedLdapServer(String mode) {
		if (StringUtils.hasLength(mode)) {
			if (this.embeddedServers.containsKey(mode) ||
					ClassUtils.isPresent(this.embeddedServers.get(mode).getClassName(), getClass().getClassLoader())) {
				return this.embeddedServers.get(mode);
			}
		}
		else {
			for (Map.Entry<String, EmbeddedLdapServer> entry : this.embeddedServers.entrySet()) {
				EmbeddedLdapServer ldapServer = entry.getValue();
				if (ClassUtils.isPresent(ldapServer.getClassName(), getClass().getClassLoader())) {
					return ldapServer;
				}
			}
		}
		return null;
	}

	private String getDefaultPort() {
		ServerSocket serverSocket = null;
		try {
			try {
				serverSocket = new ServerSocket(DEFAULT_PORT);
			}
			catch (IOException e) {
				try {
					serverSocket = new ServerSocket(0);
				}
				catch (IOException e2) {
					return String.valueOf(DEFAULT_PORT);
				}
			}
			return String.valueOf(serverSocket.getLocalPort());
		}
		finally {
			if (serverSocket != null) {
				try {
					serverSocket.close();
				}
				catch (IOException e) {
				}
			}
		}
	}

	private class EmbeddedLdapServer {

		private String beanId;

		private String className;

		private String containerClass;

		public EmbeddedLdapServer(String beanId, String className, String containerClass) {
			this.beanId = beanId;
			this.className = className;
			this.containerClass = containerClass;
		}

		public String getBeanId() {
			return this.beanId;
		}

		public String getClassName() {
			return this.className;
		}

		public String getContainerClass() {
			return this.containerClass;
		}
	}
}
