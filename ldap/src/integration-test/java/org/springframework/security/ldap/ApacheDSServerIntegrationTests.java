/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.ldap;

import java.io.IOException;
import java.net.ServerSocket;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import org.springframework.security.ldap.authentication.BindAuthenticatorTests;
import org.springframework.security.ldap.authentication.PasswordComparisonAuthenticatorTests;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearchTests;
import org.springframework.security.ldap.server.ApacheDSContainer;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulatorTests;
import org.springframework.security.ldap.userdetails.LdapUserDetailsManagerTests;

/**
 * @author Luke Taylor
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ BindAuthenticatorTests.class,
		PasswordComparisonAuthenticatorTests.class, FilterBasedLdapUserSearchTests.class,
		DefaultLdapAuthoritiesPopulatorTests.class, LdapUserDetailsManagerTests.class,
		DefaultSpringSecurityContextSourceTests.class,
		SpringSecurityLdapTemplateITests.class })
public final class ApacheDSServerIntegrationTests {
	private static ApacheDSContainer server;
	private static Integer serverPort;

	@BeforeClass
	public static void startServer() throws Exception {
		// OpenLDAP configuration
		// contextSource = new
		// DefaultSpringSecurityContextSource("ldap://127.0.0.1:22389/dc=springsource,dc=com");
		// contextSource.setUserDn("cn=admin,dc=springsource,dc=com");
		// contextSource.setPassword("password");
		server = new ApacheDSContainer("dc=springframework,dc=org",
				"classpath:test-server.ldif");
		int port = getAvailablePort();
		server.setPort(port);
		server.afterPropertiesSet();
		serverPort = port;
	}

	@AfterClass
	public static void stopServer() throws Exception {
		serverPort = null;
		if (server != null) {
			server.stop();
		}
	}

	/**
	 * Main class to allow server to be started from gradle script
	 */
	public static void main(String[] args) throws Exception {
		ApacheDSContainer server = new ApacheDSContainer("dc=springframework,dc=org",
				"classpath:test-server.ldif");
		server.afterPropertiesSet();
	}

	public static int getServerPort() {
		if (serverPort == null) {
			throw new IllegalStateException(
					"The ApacheDSContainer is not currently running");
		}
		return serverPort;
	}

	/*
	 * @After public final void reloadServerDataIfDirty() throws Exception {
	 * ClassPathResource ldifs = new ClassPathResource("test-server.ldif");
	 *
	 * if (!ldifs.getFile().exists()) { throw new IllegalStateException(
	 * "Ldif file not found: " + ldifs.getFile().getAbsolutePath()); }
	 *
	 * DirContext ctx = getContextSource().getReadWriteContext();
	 *
	 * // First of all, make sure the database is empty. Name startingPoint = new
	 * DistinguishedName("dc=springframework,dc=org");
	 *
	 * try { clearSubContexts(ctx, startingPoint); LdifFileLoader loader = new
	 * LdifFileLoader(server.getService().getAdminSession(),
	 * ldifs.getFile().getAbsolutePath()); loader.execute(); } finally { ctx.close(); } }
	 *
	 * private void clearSubContexts(DirContext ctx, Name name) throws NamingException {
	 *
	 * NamingEnumeration<Binding> enumeration = null; try { enumeration =
	 * ctx.listBindings(name); while (enumeration.hasMore()) { Binding element =
	 * enumeration.next(); DistinguishedName childName = new
	 * DistinguishedName(element.getName()); childName.prepend((DistinguishedName) name);
	 *
	 * try { ctx.destroySubcontext(childName); } catch (ContextNotEmptyException e) {
	 * clearSubContexts(ctx, childName); ctx.destroySubcontext(childName); } } }
	 * catch(NameNotFoundException ignored) { } catch (NamingException e) {
	 * e.printStackTrace(); } finally { try { enumeration.close(); } catch (Exception
	 * ignored) { } } }
	 */

	private static int getAvailablePort() throws IOException {
		ServerSocket serverSocket = null;
		try {
			serverSocket = new ServerSocket(0);
			return serverSocket.getLocalPort();
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
}
