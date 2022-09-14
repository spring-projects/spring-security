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

package org.springframework.security.ldap.server;

import java.io.InputStream;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldif.LDIFReader;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.Lifecycle;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;

/**
 * @author Eddú Meléndez
 */
public class UnboundIdContainer
		implements EmbeddedLdapServerContainer, InitializingBean, DisposableBean, Lifecycle, ApplicationContextAware {

	private InMemoryDirectoryServer directoryServer;

	private String defaultPartitionSuffix;

	private int port = 53389;

	private ApplicationContext context;

	private boolean running;

	private String ldif;

	public UnboundIdContainer(String defaultPartitionSuffix, String ldif) {
		this.defaultPartitionSuffix = defaultPartitionSuffix;
		this.ldif = ldif;
	}

	@Override
	public int getPort() {
		return this.port;
	}

	@Override
	public void setPort(int port) {
		this.port = port;
	}

	@Override
	public void destroy() {
		stop();
	}

	@Override
	public void afterPropertiesSet() {
		start();
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.context = applicationContext;
	}

	@Override
	public void start() {
		if (isRunning()) {
			return;
		}
		try {
			InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(this.defaultPartitionSuffix);
			config.addAdditionalBindCredentials("uid=admin,ou=system", "secret");
			config.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("LDAP", this.port));
			config.setEnforceSingleStructuralObjectClass(false);
			config.setEnforceAttributeSyntaxCompliance(true);
			DN dn = new DN(this.defaultPartitionSuffix);
			Entry entry = new Entry(dn);
			entry.addAttribute("objectClass", "top", "domain", "extensibleObject");
			entry.addAttribute("dc", dn.getRDN().getAttributeValues()[0]);
			InMemoryDirectoryServer directoryServer = new InMemoryDirectoryServer(config);
			directoryServer.add(entry);
			importLdif(directoryServer);
			directoryServer.startListening();
			this.port = directoryServer.getListenPort();
			this.directoryServer = directoryServer;
			this.running = true;
		}
		catch (LDAPException ex) {
			throw new RuntimeException("Server startup failed", ex);
		}
	}

	private void importLdif(InMemoryDirectoryServer directoryServer) {
		if (StringUtils.hasText(this.ldif)) {
			try {
				Resource[] resources = this.context.getResources(this.ldif);
				if (resources.length > 0) {
					if (!resources[0].exists()) {
						throw new IllegalArgumentException("Unable to find LDIF resource " + this.ldif);
					}
					try (InputStream inputStream = resources[0].getInputStream()) {
						directoryServer.importFromLDIF(false, new LDIFReader(inputStream));
					}
				}
			}
			catch (Exception ex) {
				throw new IllegalStateException("Unable to load LDIF " + this.ldif, ex);
			}
		}
	}

	@Override
	public void stop() {
		this.directoryServer.shutDown(true);
	}

	@Override
	public boolean isRunning() {
		return this.running;
	}

}
