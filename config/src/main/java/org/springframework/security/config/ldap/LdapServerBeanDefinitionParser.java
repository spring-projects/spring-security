/*
 * Copyright 2002-2020 the original author or authors.
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

import org.w3c.dom.Element;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.config.BeanIds;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.server.ApacheDSContainer;
import org.springframework.security.ldap.server.UnboundIdContainer;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;

/**
 * @author Luke Taylor
 * @author Eddú Meléndez
 * @author Evgeniy Cheban
 */
public class LdapServerBeanDefinitionParser implements BeanDefinitionParser {

	private static final String CONTEXT_SOURCE_CLASS = "org.springframework.security.ldap.DefaultSpringSecurityContextSource";

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

	private static final String RANDOM_PORT = "0";

	private static final int DEFAULT_PORT = 33389;

	private static final String APACHEDS_CLASSNAME = "org.apache.directory.server.core.DefaultDirectoryService";

	private static final String UNBOUNID_CLASSNAME = "com.unboundid.ldap.listener.InMemoryDirectoryServer";

	private static final String APACHEDS_CONTAINER_CLASSNAME = "org.springframework.security.ldap.server.ApacheDSContainer";

	private static final String UNBOUNDID_CONTAINER_CLASSNAME = "org.springframework.security.ldap.server.UnboundIdContainer";

	@Override
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
				parserContext.getReaderContext()
						.error("You must specify the " + ATT_PASSWORD + " if you supply a " + managerDn, elt);
			}

			contextSource.getPropertyValues().addPropertyValue("userDn", managerDn);
			contextSource.getPropertyValues().addPropertyValue("password", managerPassword);
		}

		String id = elt.getAttribute(AbstractBeanDefinitionParser.ID_ATTRIBUTE);

		String contextSourceId = StringUtils.hasText(id) ? id : BeanIds.CONTEXT_SOURCE;

		parserContext.getRegistry().registerBeanDefinition(contextSourceId, contextSource);

		return null;
	}

	/**
	 * Will be called if no url attribute is supplied.
	 *
	 * Registers beans to create an embedded apache directory server.
	 * @return the BeanDefinition for the ContextSource for the embedded server.
	 *
	 * @see ApacheDSContainer
	 * @see UnboundIdContainer
	 */
	private RootBeanDefinition createEmbeddedServer(Element element, ParserContext parserContext) {
		Object source = parserContext.extractSource(element);

		String suffix = element.getAttribute(ATT_ROOT_SUFFIX);

		if (!StringUtils.hasText(suffix)) {
			suffix = OPT_DEFAULT_ROOT_SUFFIX;
		}

		BeanDefinitionBuilder contextSource = BeanDefinitionBuilder.rootBeanDefinition(CONTEXT_SOURCE_CLASS);
		contextSource.addConstructorArgValue(suffix);
		contextSource.addPropertyValue("userDn", "uid=admin,ou=system");
		contextSource.addPropertyValue("password", "secret");

		BeanDefinition embeddedLdapServerConfigBean = BeanDefinitionBuilder
				.rootBeanDefinition(EmbeddedLdapServerConfigBean.class).getBeanDefinition();
		String embeddedLdapServerConfigBeanName = parserContext.getReaderContext()
				.generateBeanName(embeddedLdapServerConfigBean);

		parserContext.registerBeanComponent(
				new BeanComponentDefinition(embeddedLdapServerConfigBean, embeddedLdapServerConfigBeanName));

		contextSource.setFactoryMethodOnBean("createEmbeddedContextSource", embeddedLdapServerConfigBeanName);

		String mode = element.getAttribute("mode");
		RootBeanDefinition ldapContainer = getRootBeanDefinition(mode);
		ldapContainer.setSource(source);
		ldapContainer.getConstructorArgumentValues().addGenericArgumentValue(suffix);

		String ldifs = element.getAttribute(ATT_LDIF_FILE);
		if (!StringUtils.hasText(ldifs)) {
			ldifs = OPT_DEFAULT_LDIF_FILE;
		}

		ldapContainer.getConstructorArgumentValues().addGenericArgumentValue(ldifs);
		ldapContainer.getPropertyValues().addPropertyValue("port", getPort(element));

		if (parserContext.getRegistry().containsBeanDefinition(BeanIds.EMBEDDED_APACHE_DS)
				|| parserContext.getRegistry().containsBeanDefinition(BeanIds.EMBEDDED_UNBOUNDID)) {
			parserContext.getReaderContext().error("Only one embedded server bean is allowed per application context",
					element);
		}

		String beanId = resolveBeanId(mode);
		if (beanId != null) {
			parserContext.getRegistry().registerBeanDefinition(beanId, ldapContainer);
		}

		return (RootBeanDefinition) contextSource.getBeanDefinition();
	}

	private RootBeanDefinition getRootBeanDefinition(String mode) {
		if (isApacheDsEnabled(mode)) {
			return new RootBeanDefinition(APACHEDS_CONTAINER_CLASSNAME, null, null);
		}
		else if (isUnboundidEnabled(mode)) {
			return new RootBeanDefinition(UNBOUNDID_CONTAINER_CLASSNAME, null, null);
		}
		throw new IllegalStateException("Embedded LDAP server is not provided");
	}

	private String resolveBeanId(String mode) {
		if (isApacheDsEnabled(mode)) {
			return BeanIds.EMBEDDED_APACHE_DS;
		}
		else if (isUnboundidEnabled(mode)) {
			return BeanIds.EMBEDDED_UNBOUNDID;
		}
		return null;
	}

	private boolean isApacheDsEnabled(String mode) {
		return "apacheds".equals(mode) || ClassUtils.isPresent(APACHEDS_CLASSNAME, getClass().getClassLoader());
	}

	private boolean isUnboundidEnabled(String mode) {
		return "unboundid".equals(mode) || ClassUtils.isPresent(UNBOUNID_CLASSNAME, getClass().getClassLoader());
	}

	private String getPort(Element element) {
		String port = element.getAttribute(ATT_PORT);
		return (StringUtils.hasText(port) ? port : getDefaultPort());
	}

	private String getDefaultPort() {
		try (ServerSocket serverSocket = new ServerSocket(DEFAULT_PORT)) {
			return String.valueOf(serverSocket.getLocalPort());
		}
		catch (IOException ex) {
			return RANDOM_PORT;
		}
	}

	private static class EmbeddedLdapServerConfigBean implements ApplicationContextAware {

		private ApplicationContext applicationContext;

		@Override
		public void setApplicationContext(ApplicationContext applicationContext) {
			this.applicationContext = applicationContext;
		}

		@SuppressWarnings("unused")
		private DefaultSpringSecurityContextSource createEmbeddedContextSource(String suffix) {
			int port;
			if (ClassUtils.isPresent(APACHEDS_CLASSNAME, getClass().getClassLoader())) {
				ApacheDSContainer apacheDSContainer = this.applicationContext.getBean(ApacheDSContainer.class);
				port = apacheDSContainer.getLocalPort();
			}
			else if (ClassUtils.isPresent(UNBOUNID_CLASSNAME, getClass().getClassLoader())) {
				UnboundIdContainer unboundIdContainer = this.applicationContext.getBean(UnboundIdContainer.class);
				port = unboundIdContainer.getPort();
			}
			else {
				throw new IllegalStateException("Embedded LDAP server is not provided");
			}

			String providerUrl = "ldap://127.0.0.1:" + port + "/" + suffix;

			return new DefaultSpringSecurityContextSource(providerUrl);
		}

	}

}
