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

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.authn.AuthenticationInterceptor;
import org.apache.directory.server.core.entry.ServerEntry;
import org.apache.directory.server.core.exception.ExceptionInterceptor;
import org.apache.directory.server.core.interceptor.Interceptor;
import org.apache.directory.server.core.normalization.NormalizationInterceptor;
import org.apache.directory.server.core.operational.OperationalAttributeInterceptor;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.core.referral.ReferralInterceptor;
import org.apache.directory.server.core.subtree.SubentryInterceptor;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.protocol.shared.store.LdifFileLoader;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.shared.ldap.exception.LdapNameNotFoundException;
import org.apache.directory.shared.ldap.name.LdapDN;
import org.apache.mina.transport.socket.SocketAcceptor;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.Lifecycle;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.util.Assert;

/**
 * Provides lifecycle services for the embedded apacheDS server defined by the supplied
 * configuration. Used by {@code LdapServerBeanDefinitionParser}. An instance will be
 * stored in the application context for each embedded server instance. It will start the
 * server when the context is initialized and shut it down when it is closed. It is
 * intended for temporary embedded use and will not retain changes across start/stop
 * boundaries. The working directory is deleted on shutdown.
 *
 * <p>
 * If used repeatedly in a single JVM process with the same configuration (for example,
 * when repeatedly loading an application context during testing), it's important that the
 * application context is closed to allow the bean to be disposed of and the server
 * shutdown prior to attempting to start it again.
 * <p>
 * This class is intended for testing and internal security namespace use, only, and is
 * not considered part of the framework's public API.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @author Gunnar Hillert
 * @author Evgeniy Cheban
 * @deprecated Use {@link UnboundIdContainer} instead because ApacheDS 1.x is no longer
 * supported with no GA version to replace it.
 */
@Deprecated
public class ApacheDSContainer
		implements EmbeddedLdapServerContainer, InitializingBean, DisposableBean, Lifecycle, ApplicationContextAware {

	private final Log logger = LogFactory.getLog(getClass());

	final DefaultDirectoryService service;

	LdapServer server;

	private TcpTransport transport;

	private ApplicationContext ctxt;

	private File workingDir;

	private boolean running;

	private final String ldifResources;

	private final JdbmPartition partition;

	private final String root;

	private int port = 53389;

	private int localPort;

	private boolean ldapOverSslEnabled;

	private File keyStoreFile;

	private String certificatePassord;

	public ApacheDSContainer(String root, String ldifs) throws Exception {
		this.ldifResources = ldifs;
		this.service = new DefaultDirectoryService();
		List<Interceptor> list = new ArrayList<>();
		list.add(new NormalizationInterceptor());
		list.add(new AuthenticationInterceptor());
		list.add(new ReferralInterceptor());
		list.add(new ExceptionInterceptor());
		list.add(new OperationalAttributeInterceptor());
		list.add(new SubentryInterceptor());
		this.service.setInterceptors(list);
		this.partition = new JdbmPartition();
		this.partition.setId("rootPartition");
		this.partition.setSuffix(root);
		this.root = root;
		this.service.addPartition(this.partition);
		this.service.setExitVmOnShutdown(false);
		this.service.setShutdownHookEnabled(false);
		this.service.getChangeLog().setEnabled(false);
		this.service.setDenormalizeOpAttrsEnabled(true);
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		if (this.workingDir == null) {
			String apacheWorkDir = System.getProperty("apacheDSWorkDir");
			if (apacheWorkDir == null) {
				apacheWorkDir = createTempDirectory("apacheds-spring-security-");
			}
			setWorkingDirectory(new File(apacheWorkDir));
		}
		Assert.isTrue(!this.ldapOverSslEnabled || this.keyStoreFile != null,
				"When LdapOverSsl is enabled, the keyStoreFile property must be set.");
		this.server = new LdapServer();
		this.server.setDirectoryService(this.service);
		// AbstractLdapIntegrationTests assume IPv4, so we specify the same here
		this.transport = new TcpTransport(this.port);
		if (this.ldapOverSslEnabled) {
			this.transport.setEnableSSL(true);
			this.server.setKeystoreFile(this.keyStoreFile.getAbsolutePath());
			this.server.setCertificatePassword(this.certificatePassord);
		}
		this.server.setTransports(this.transport);
		start();
	}

	@Override
	public void destroy() {
		stop();
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.ctxt = applicationContext;
	}

	public void setWorkingDirectory(File workingDir) {
		Assert.notNull(workingDir, "workingDir cannot be null");
		this.logger.info("Setting working directory for LDAP_PROVIDER: " + workingDir.getAbsolutePath());
		Assert.isTrue(!workingDir.exists(),
				"The specified working directory '" + workingDir.getAbsolutePath()
						+ "' already exists. Another directory service instance may be using it or it may be from a "
						+ " previous unclean shutdown. Please confirm and delete it or configure a different "
						+ "working directory");
		this.workingDir = workingDir;
		this.service.setWorkingDirectory(workingDir);
	}

	@Override
	public void setPort(int port) {
		this.port = port;
	}

	@Override
	public int getPort() {
		return this.port;
	}

	/**
	 * Returns the port that is resolved by {@link TcpTransport}.
	 * @return the port that is resolved by {@link TcpTransport}
	 */
	public int getLocalPort() {
		return this.localPort;
	}

	/**
	 * If set to {@code true} will enable LDAP over SSL (LDAPs). If set to {@code true}
	 * {@link ApacheDSContainer#setCertificatePassord(String)} must be set as well.
	 * @param ldapOverSslEnabled If not set, will default to false
	 */
	public void setLdapOverSslEnabled(boolean ldapOverSslEnabled) {
		this.ldapOverSslEnabled = ldapOverSslEnabled;
	}

	/**
	 * The keyStore must not be null and must be a valid file. Will set the keyStore file
	 * on the underlying {@link LdapServer}.
	 * @param keyStoreFile Mandatory if LDAPs is enabled
	 */
	public void setKeyStoreFile(File keyStoreFile) {
		Assert.notNull(keyStoreFile, "The keyStoreFile must not be null.");
		Assert.isTrue(keyStoreFile.isFile(), "The keyStoreFile must be a file.");
		this.keyStoreFile = keyStoreFile;
	}

	/**
	 * Will set the certificate password on the underlying {@link LdapServer}.
	 * @param certificatePassord May be null
	 */
	public void setCertificatePassord(String certificatePassord) {
		this.certificatePassord = certificatePassord;
	}

	public DefaultDirectoryService getService() {
		return this.service;
	}

	@Override
	public void start() {
		if (isRunning()) {
			return;
		}
		Assert.state(!this.service.isStarted(), "DirectoryService is already running.");
		this.logger.info("Starting directory server...");
		try {
			this.service.startup();
			this.server.start();
		}
		catch (Exception ex) {
			throw new RuntimeException("Server startup failed", ex);
		}
		try {
			this.service.getAdminSession().lookup(this.partition.getSuffixDn());
		}
		catch (LdapNameNotFoundException ex) {
			handleLdapNameNotFoundException();
		}
		catch (Exception ex) {
			this.logger.error("Lookup failed", ex);
		}
		SocketAcceptor socketAcceptor = this.server.getSocketAcceptor(this.transport);
		InetSocketAddress localAddress = socketAcceptor.getLocalAddress();
		this.localPort = localAddress.getPort();
		this.running = true;
		try {
			importLdifs();
		}
		catch (Exception ex) {
			throw new RuntimeException("Failed to import LDIF file(s)", ex);
		}
	}

	private void handleLdapNameNotFoundException() {
		try {
			LdapDN dn = new LdapDN(this.root);
			Assert.isTrue(this.root.startsWith("dc="), "root must start with dc=");
			String dc = this.root.substring(3, this.root.indexOf(','));
			ServerEntry entry = this.service.newEntry(dn);
			entry.add("objectClass", "top", "domain", "extensibleObject");
			entry.add("dc", dc);
			this.service.getAdminSession().add(entry);
		}
		catch (Exception ex) {
			this.logger.error("Failed to create dc entry", ex);
		}
	}

	@Override
	public void stop() {
		if (!isRunning()) {
			return;
		}
		this.logger.info("Shutting down directory server ...");
		try {
			this.server.stop();
			this.service.shutdown();
		}
		catch (Exception ex) {
			this.logger.error("Shutdown failed", ex);
			return;
		}
		this.running = false;
		if (this.workingDir.exists()) {
			this.logger.info("Deleting working directory " + this.workingDir.getAbsolutePath());
			deleteDir(this.workingDir);
		}
	}

	private void importLdifs() throws Exception {
		// Import any ldif files
		Resource[] ldifs = (this.ctxt != null) ? this.ctxt.getResources(this.ldifResources)
				: new PathMatchingResourcePatternResolver().getResources(this.ldifResources);
		// Note that we can't just import using the ServerContext returned
		// from starting Apache DS, apparently because of the long-running issue
		// DIRSERVER-169.
		// We need a standard context.
		// DirContext dirContext = contextSource.getReadWriteContext();
		if (ldifs == null || ldifs.length == 0) {
			return;
		}
		Assert.isTrue(ldifs.length == 1, () -> "More than one LDIF resource found with the supplied pattern:"
				+ this.ldifResources + " Got " + Arrays.toString(ldifs));
		String ldifFile = getLdifFile(ldifs);
		this.logger.info("Loading LDIF file: " + ldifFile);
		LdifFileLoader loader = new LdifFileLoader(this.service.getAdminSession(), new File(ldifFile), null,
				getClass().getClassLoader());
		loader.execute();
	}

	private String getLdifFile(Resource[] ldifs) throws IOException {
		try {
			return ldifs[0].getFile().getAbsolutePath();
		}
		catch (IOException ex) {
			return ldifs[0].getURI().toString();
		}
	}

	private String createTempDirectory(String prefix) throws IOException {
		String parentTempDir = System.getProperty("java.io.tmpdir");
		String fileNamePrefix = prefix + System.nanoTime();
		String fileName = fileNamePrefix;
		for (int i = 0; i < 1000; i++) {
			File tempDir = new File(parentTempDir, fileName);
			if (!tempDir.exists()) {
				return tempDir.getAbsolutePath();
			}
			fileName = fileNamePrefix + "~" + i;
		}
		throw new IOException(
				"Failed to create a temporary directory for file at " + new File(parentTempDir, fileNamePrefix));
	}

	private boolean deleteDir(File dir) {
		if (dir.isDirectory()) {
			String[] children = dir.list();
			for (String child : children) {
				boolean success = deleteDir(new File(dir, child));
				if (!success) {
					return false;
				}
			}
		}
		return dir.delete();
	}

	@Override
	public boolean isRunning() {
		return this.running;
	}

}
