/*
 * Copyright 2002-2022 the original author or authors.
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

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.Lifecycle;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.server.EmbeddedLdapServerContainer;
import org.springframework.security.ldap.server.UnboundIdContainer;
import org.springframework.util.ClassUtils;

/**
 * Creates a {@link DefaultSpringSecurityContextSource} used to perform LDAP
 * authentication and starts and in-memory LDAP server.
 *
 * @author Eleftheria Stein
 * @since 5.7
 */
public class EmbeddedLdapServerContextSourceFactoryBean
		implements FactoryBean<DefaultSpringSecurityContextSource>, DisposableBean, ApplicationContextAware {

	private static final String UNBOUNDID_CLASSNAME = "com.unboundid.ldap.listener.InMemoryDirectoryServer";

	private static final int DEFAULT_PORT = 33389;

	private static final int RANDOM_PORT = 0;

	private Integer port;

	private String ldif = "classpath*:*.ldif";

	private String root = "dc=springframework,dc=org";

	private ApplicationContext context;

	private String managerDn;

	private String managerPassword;

	private EmbeddedLdapServerContainer container;

	/**
	 * Create an EmbeddedLdapServerContextSourceFactoryBean that will use an embedded LDAP
	 * server to perform LDAP authentication. This requires a dependency on
	 * `com.unboundid:unboundid-ldapsdk`.
	 * @return the EmbeddedLdapServerContextSourceFactoryBean
	 */
	public static EmbeddedLdapServerContextSourceFactoryBean fromEmbeddedLdapServer() {
		return new EmbeddedLdapServerContextSourceFactoryBean();
	}

	/**
	 * Specifies an LDIF to load at startup for an embedded LDAP server. The default is
	 * "classpath*:*.ldif".
	 * @param ldif the ldif to load at startup for an embedded LDAP server.
	 */
	public void setLdif(String ldif) {
		this.ldif = ldif;
	}

	/**
	 * The port to connect to LDAP to (the default is 33389 or random available port if
	 * unavailable). Supplying 0 as the port indicates that a random available port should
	 * be selected.
	 * @param port the port to connect to
	 */
	public void setPort(int port) {
		this.port = port;
	}

	/**
	 * Optional root suffix for the embedded LDAP server. Default is
	 * "dc=springframework,dc=org".
	 * @param root root suffix for the embedded LDAP server
	 */
	public void setRoot(String root) {
		this.root = root;
	}

	/**
	 * Username (DN) of the "manager" user identity (i.e. "uid=admin,ou=system") which
	 * will be used to authenticate to an LDAP server. If omitted, anonymous access will
	 * be used.
	 * @param managerDn the username (DN) of the "manager" user identity used to
	 * authenticate to a LDAP server.
	 */
	public void setManagerDn(String managerDn) {
		this.managerDn = managerDn;
	}

	/**
	 * The password for the manager DN. This is required if the
	 * {@link #setManagerDn(String)} is specified.
	 * @param managerPassword password for the manager DN
	 */
	public void setManagerPassword(String managerPassword) {
		this.managerPassword = managerPassword;
	}

	@Override
	public DefaultSpringSecurityContextSource getObject() throws Exception {
		if (!ClassUtils.isPresent(UNBOUNDID_CLASSNAME, getClass().getClassLoader())) {
			throw new IllegalStateException("Embedded LDAP server is not provided");
		}
		this.container = getContainer();
		this.port = this.container.getPort();
		DefaultSpringSecurityContextSource contextSourceFromProviderUrl = new DefaultSpringSecurityContextSource(
				"ldap://127.0.0.1:" + this.port + "/" + this.root);
		if (this.managerDn != null) {
			contextSourceFromProviderUrl.setUserDn(this.managerDn);
			if (this.managerPassword == null) {
				throw new IllegalStateException("managerPassword is required if managerDn is supplied");
			}
			contextSourceFromProviderUrl.setPassword(this.managerPassword);
		}
		contextSourceFromProviderUrl.afterPropertiesSet();
		return contextSourceFromProviderUrl;
	}

	@Override
	public Class<?> getObjectType() {
		return DefaultSpringSecurityContextSource.class;
	}

	@Override
	public void destroy() {
		if (this.container instanceof Lifecycle) {
			((Lifecycle) this.container).stop();
		}
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.context = applicationContext;
	}

	private EmbeddedLdapServerContainer getContainer() {
		if (!ClassUtils.isPresent(UNBOUNDID_CLASSNAME, getClass().getClassLoader())) {
			throw new IllegalStateException("Embedded LDAP server is not provided");
		}
		UnboundIdContainer unboundIdContainer = new UnboundIdContainer(this.root, this.ldif);
		unboundIdContainer.setApplicationContext(this.context);
		unboundIdContainer.setPort(getEmbeddedServerPort());
		unboundIdContainer.afterPropertiesSet();
		return unboundIdContainer;
	}

	private int getEmbeddedServerPort() {
		if (this.port == null) {
			this.port = getDefaultEmbeddedServerPort();
		}
		return this.port;
	}

	private int getDefaultEmbeddedServerPort() {
		try (ServerSocket serverSocket = new ServerSocket(DEFAULT_PORT)) {
			return serverSocket.getLocalPort();
		}
		catch (IOException ex) {
			return RANDOM_PORT;
		}
	}

}
