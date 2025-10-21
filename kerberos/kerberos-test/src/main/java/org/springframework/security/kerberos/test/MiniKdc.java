/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.kerberos.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.util.IOUtil;
import org.apache.kerby.util.NetworkUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Mini KDC based on Apache Directory Server that can be embedded in testcases or used
 * from command line as a standalone KDC.
 * <p>
 * <b>From within testcases:</b>
 * <p>
 * MiniKdc sets one System property when started and un-set when stopped:
 * <ul>
 * <li>sun.security.krb5.debug: set to the debug value provided in the configuration</li>
 * </ul>
 * Because of this, multiple MiniKdc instances cannot be started in parallel. For example,
 * running testcases in parallel that start a KDC each. To accomplish this a single
 * MiniKdc should be used for all testcases running in parallel.
 * <p>
 * MiniKdc default configuration values are:
 * <ul>
 * <li>org.name=EXAMPLE (used to create the REALM)</li>
 * <li>org.domain=COM (used to create the REALM)</li>
 * <li>kdc.bind.address=localhost</li>
 * <li>kdc.port=0 (ephemeral port)</li>
 * <li>instance=DefaultKrbServer</li>
 * <li>max.ticket.lifetime=86400000 (1 day)</li>
 * <li>max.renewable.lifetime=604800000 (7 days)</li>
 * <li>transport=TCP</li>
 * <li>debug=false</li>
 * </ul>
 * The generated krb5.conf forces TCP connections.
 *
 * @author Original Hadoop MiniKdc Authors
 * @author Janne Valkealahti
 * @author Bogdan Mustiata
 */
public class MiniKdc {

	public static final String JAVA_SECURITY_KRB5_CONF = "java.security.krb5.conf";

	public static final String SUN_SECURITY_KRB5_DEBUG = "sun.security.krb5.debug";

	public static void main(String[] args) throws Exception {
		if (args.length < 4) {
			System.out.println("Arguments: <WORKDIR> <MINIKDCPROPERTIES> " + "<KEYTABFILE> [<PRINCIPALS>]+");
			System.exit(1);
		}
		File workDir = new File(args[0]);
		if (!workDir.exists()) {
			throw new RuntimeException("Specified work directory does not exists: " + workDir.getAbsolutePath());
		}
		Properties conf = createConf();
		File file = new File(args[1]);
		if (!file.exists()) {
			throw new RuntimeException("Specified configuration does not exists: " + file.getAbsolutePath());
		}
		Properties userConf = new Properties();
		InputStreamReader r = null;
		try {
			r = new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8);
			userConf.load(r);
		}
		finally {
			if (r != null) {
				r.close();
			}
		}
		for (Map.Entry<?, ?> entry : userConf.entrySet()) {
			conf.put(entry.getKey(), entry.getValue());
		}
		final MiniKdc miniKdc = new MiniKdc(conf, workDir);
		miniKdc.start();
		File krb5conf = new File(workDir, "krb5.conf");
		if (miniKdc.getKrb5conf().renameTo(krb5conf)) {
			File keytabFile = new File(args[2]).getAbsoluteFile();
			String[] principals = new String[args.length - 3];
			System.arraycopy(args, 3, principals, 0, args.length - 3);
			miniKdc.createPrincipal(keytabFile, principals);
			System.out.println();
			System.out.println("Standalone MiniKdc Running");
			System.out.println("---------------------------------------------------");
			System.out.println("  Realm           : " + miniKdc.getRealm());
			System.out.println("  Running at      : " + miniKdc.getHost() + ":" + miniKdc.getPort());
			System.out.println("  krb5conf        : " + krb5conf);
			System.out.println();
			System.out.println("  created keytab  : " + keytabFile);
			System.out.println("  with principals : " + Arrays.asList(principals));
			System.out.println();
			System.out.println(" Do <CTRL-C> or kill <PID> to stop it");
			System.out.println("---------------------------------------------------");
			System.out.println();
			Runtime.getRuntime().addShutdownHook(new Thread() {
				@Override
				public void run() {
					miniKdc.stop();
				}
			});
		}
		else {
			throw new RuntimeException("Cannot rename KDC's krb5conf to " + krb5conf.getAbsolutePath());
		}
	}

	private static final Logger LOG = LoggerFactory.getLogger(MiniKdc.class);

	public static final String ORG_NAME = "org.name";

	public static final String ORG_DOMAIN = "org.domain";

	public static final String KDC_BIND_ADDRESS = "kdc.bind.address";

	public static final String KDC_PORT = "kdc.port";

	public static final String INSTANCE = "instance";

	public static final String MAX_TICKET_LIFETIME = "max.ticket.lifetime";

	public static final String MIN_TICKET_LIFETIME = "min.ticket.lifetime";

	public static final String MAX_RENEWABLE_LIFETIME = "max.renewable.lifetime";

	public static final String TRANSPORT = "transport";

	public static final String DEBUG = "debug";

	private static final Set<String> PROPERTIES = new HashSet<String>();

	private static final Properties DEFAULT_CONFIG = new Properties();

	static {
		PROPERTIES.add(ORG_NAME);
		PROPERTIES.add(ORG_DOMAIN);
		PROPERTIES.add(KDC_BIND_ADDRESS);
		PROPERTIES.add(KDC_BIND_ADDRESS);
		PROPERTIES.add(KDC_PORT);
		PROPERTIES.add(INSTANCE);
		PROPERTIES.add(TRANSPORT);
		PROPERTIES.add(MAX_TICKET_LIFETIME);
		PROPERTIES.add(MAX_RENEWABLE_LIFETIME);

		DEFAULT_CONFIG.setProperty(KDC_BIND_ADDRESS, "localhost");
		DEFAULT_CONFIG.setProperty(KDC_PORT, "0");
		DEFAULT_CONFIG.setProperty(INSTANCE, "DefaultKrbServer");
		DEFAULT_CONFIG.setProperty(ORG_NAME, "EXAMPLE");
		DEFAULT_CONFIG.setProperty(ORG_DOMAIN, "COM");
		DEFAULT_CONFIG.setProperty(TRANSPORT, "TCP");
		DEFAULT_CONFIG.setProperty(MAX_TICKET_LIFETIME, "86400000");
		DEFAULT_CONFIG.setProperty(MAX_RENEWABLE_LIFETIME, "604800000");
		DEFAULT_CONFIG.setProperty(DEBUG, "false");
	}

	/**
	 * Convenience method that returns MiniKdc default configuration.
	 * <p>
	 * The returned configuration is a copy, it can be customized before using it to
	 * create a MiniKdc.
	 * @return a MiniKdc default configuration.
	 */
	public static Properties createConf() {
		return (Properties) DEFAULT_CONFIG.clone();
	}

	private Properties conf;

	private SimpleKdcServer simpleKdc;

	private int port;

	private String realm;

	private File workDir;

	private File krb5conf;

	private String transport;

	private boolean krb5Debug;

	public void setTransport(String transport) {
		this.transport = transport;
	}

	/**
	 * Creates a MiniKdc.
	 * @param conf MiniKdc configuration.
	 * @param workDir working directory, it should be the build directory. Under this
	 * directory an ApacheDS working directory will be created, this directory will be
	 * deleted when the MiniKdc stops.
	 * @throws Exception thrown if the MiniKdc could not be created.
	 */
	public MiniKdc(Properties conf, File workDir) throws Exception {
		if (!conf.keySet().containsAll(PROPERTIES)) {
			Set<String> missingProperties = new HashSet<String>(PROPERTIES);
			missingProperties.removeAll(conf.keySet());
			throw new IllegalArgumentException("Missing configuration properties: " + missingProperties);
		}
		this.workDir = new File(workDir, Long.toString(System.currentTimeMillis()));
		if (!this.workDir.exists() && !this.workDir.mkdirs()) {
			throw new RuntimeException("Cannot create directory " + this.workDir);
		}
		LOG.info("Configuration:");
		LOG.info("---------------------------------------------------------------");
		for (Map.Entry<?, ?> entry : conf.entrySet()) {
			LOG.info("  {}: {}", entry.getKey(), entry.getValue());
		}
		LOG.info("---------------------------------------------------------------");
		this.conf = conf;
		this.port = Integer.parseInt(conf.getProperty(KDC_PORT));
		String orgName = conf.getProperty(ORG_NAME);
		String orgDomain = conf.getProperty(ORG_DOMAIN);
		this.realm = orgName.toUpperCase(Locale.ENGLISH) + "." + orgDomain.toUpperCase(Locale.ENGLISH);
	}

	/**
	 * Returns the port of the MiniKdc.
	 * @return the port of the MiniKdc.
	 */
	public int getPort() {
		return this.port;
	}

	/**
	 * Returns the host of the MiniKdc.
	 * @return the host of the MiniKdc.
	 */
	public String getHost() {
		return this.conf.getProperty(KDC_BIND_ADDRESS);
	}

	/**
	 * Returns the realm of the MiniKdc.
	 * @return the realm of the MiniKdc.
	 */
	public String getRealm() {
		return this.realm;
	}

	public File getKrb5conf() {
		this.krb5conf = new File(System.getProperty(JAVA_SECURITY_KRB5_CONF));
		return this.krb5conf;
	}

	/**
	 * Starts the MiniKdc.
	 * @throws Exception thrown if the MiniKdc could not be started.
	 */
	public synchronized void start() throws Exception {
		if (this.simpleKdc != null) {
			throw new RuntimeException("Already started");
		}
		this.simpleKdc = new SimpleKdcServer();
		prepareKdcServer();
		this.simpleKdc.init();
		resetDefaultRealm();
		this.simpleKdc.start();
		LOG.info("MiniKdc started.");
	}

	private void resetDefaultRealm() throws IOException {
		InputStream templateResource = new FileInputStream(getKrb5conf().getAbsolutePath());
		String content = IOUtil.readInput(templateResource);
		content = content.replaceAll("default_realm = .*\n", "default_realm = " + getRealm() + "\n");
		IOUtil.writeFile(content, getKrb5conf());
	}

	private void prepareKdcServer() throws Exception {
		// transport
		this.simpleKdc.setWorkDir(this.workDir);
		this.simpleKdc.setKdcHost(getHost());
		this.simpleKdc.setKdcRealm(this.realm);
		if (this.transport == null) {
			this.transport = this.conf.getProperty(TRANSPORT);
		}
		if (this.port == 0) {
			this.port = NetworkUtil.getServerPort();
		}
		if (this.transport != null) {
			if (this.transport.trim().equals("TCP")) {
				this.simpleKdc.setKdcTcpPort(this.port);
				this.simpleKdc.setAllowUdp(false);
			}
			else if (this.transport.trim().equals("UDP")) {
				this.simpleKdc.setKdcUdpPort(this.port);
				this.simpleKdc.setAllowTcp(false);
			}
			else {
				throw new IllegalArgumentException("Invalid transport: " + this.transport);
			}
		}
		else {
			throw new IllegalArgumentException("Need to set transport!");
		}
		this.simpleKdc.getKdcConfig().setString(KdcConfigKey.KDC_SERVICE_NAME, this.conf.getProperty(INSTANCE));
		if (this.conf.getProperty(DEBUG) != null) {
			this.krb5Debug = getAndSet(SUN_SECURITY_KRB5_DEBUG, this.conf.getProperty(DEBUG));
		}
		if (this.conf.getProperty(MIN_TICKET_LIFETIME) != null) {
			this.simpleKdc.getKdcConfig()
				.setLong(KdcConfigKey.MINIMUM_TICKET_LIFETIME,
						Long.parseLong(this.conf.getProperty(MIN_TICKET_LIFETIME)));
		}
		if (this.conf.getProperty(MAX_TICKET_LIFETIME) != null) {
			this.simpleKdc.getKdcConfig()
				.setLong(KdcConfigKey.MAXIMUM_TICKET_LIFETIME,
						Long.parseLong(this.conf.getProperty(MiniKdc.MAX_TICKET_LIFETIME)));
		}
	}

	/**
	 * Stops the MiniKdc
	 */
	public synchronized void stop() {
		if (this.simpleKdc != null) {
			try {
				this.simpleKdc.stop();
			}
			catch (KrbException ex) {
				ex.printStackTrace();
			}
			finally {
				if (this.conf.getProperty(DEBUG) != null) {
					System.setProperty(SUN_SECURITY_KRB5_DEBUG, Boolean.toString(this.krb5Debug));
				}
			}
		}
		delete(this.workDir);
		try {
			// Will be fixed in next Kerby version.
			Thread.sleep(1000);
		}
		catch (InterruptedException ex) {
			ex.printStackTrace();
		}
		LOG.info("MiniKdc stopped.");
	}

	private void delete(File f) {
		if (f.isFile()) {
			if (!f.delete()) {
				LOG.warn("WARNING: cannot delete file " + f.getAbsolutePath());
			}
		}
		else {
			File[] fileList = f.listFiles();
			if (fileList != null) {
				for (File c : fileList) {
					delete(c);
				}
			}
			if (!f.delete()) {
				LOG.warn("WARNING: cannot delete directory " + f.getAbsolutePath());
			}
		}
	}

	/**
	 * Creates a principal in the KDC with the specified user and password.
	 * @param principal principal name, do not include the domain.
	 * @param password password.
	 * @throws Exception thrown if the principal could not be created.
	 */
	public synchronized void createPrincipal(String principal, String password) throws Exception {
		this.simpleKdc.createPrincipal(principal, password);
	}

	/**
	 * Creates multiple principals in the KDC and adds them to a keytab file.
	 * @param keytabFile keytab file to add the created principals.
	 * @param principals principals to add to the KDC, do not include the domain.
	 * @throws Exception thrown if the principals or the keytab file could not be created.
	 */
	public synchronized void createPrincipal(File keytabFile, String... principals) throws Exception {
		this.simpleKdc.createPrincipals(principals);
		if (keytabFile.exists() && !keytabFile.delete()) {
			LOG.error("Failed to delete keytab file: " + keytabFile);
		}
		for (String principal : principals) {
			this.simpleKdc.getKadmin().exportKeytab(keytabFile, principal);
		}
	}

	/**
	 * Set the System property; return the old value for caching.
	 * @param sysprop property
	 * @param debug true or false
	 * @return the previous value
	 */
	private boolean getAndSet(String sysprop, String debug) {
		boolean old = Boolean.getBoolean(sysprop);
		System.setProperty(sysprop, debug);
		return old;
	}

}
