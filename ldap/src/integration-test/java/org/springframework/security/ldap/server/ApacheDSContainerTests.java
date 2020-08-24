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

package org.springframework.security.ldap.server;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.List;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import org.springframework.core.io.ClassPathResource;
import org.springframework.util.FileCopyUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.fail;

/**
 * Useful for debugging the container by itself.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @author Gunnar Hillert
 * @author Evgeniy Cheban
 * @since 3.0
 */
public class ApacheDSContainerTests {

	@Rule
	public TemporaryFolder temporaryFolder = new TemporaryFolder();

	// SEC-2162
	@Test
	public void failsToStartThrowsException() throws Exception {
		ApacheDSContainer server1 = new ApacheDSContainer("dc=springframework,dc=org", "classpath:test-server.ldif");
		ApacheDSContainer server2 = new ApacheDSContainer("dc=springframework,dc=org", "classpath:missing.ldif");
		List<Integer> ports = getDefaultPorts(1);
		server1.setPort(ports.get(0));
		server2.setPort(ports.get(0));
		try {
			server1.afterPropertiesSet();
			try {
				server2.afterPropertiesSet();
				fail("Expected Exception");
			}
			catch (RuntimeException success) {
			}
		}
		finally {
			try {
				server1.destroy();
			}
			catch (Throwable ex) {
			}
			try {
				server2.destroy();
			}
			catch (Throwable ex) {
			}
		}
	}

	// SEC-2161
	@Test
	public void multipleInstancesSimultanciously() throws Exception {
		ApacheDSContainer server1 = new ApacheDSContainer("dc=springframework,dc=org", "classpath:test-server.ldif");
		ApacheDSContainer server2 = new ApacheDSContainer("dc=springframework,dc=org", "classpath:test-server.ldif");
		List<Integer> ports = getDefaultPorts(2);
		server1.setPort(ports.get(0));
		server2.setPort(ports.get(1));
		try {
			server1.afterPropertiesSet();
			server2.afterPropertiesSet();
		}
		finally {
			try {
				server1.destroy();
			}
			catch (Throwable ex) {
			}
			try {
				server2.destroy();
			}
			catch (Throwable ex) {
			}
		}
	}

	@Test
	public void startWithLdapOverSslWithoutCertificate() throws Exception {
		ApacheDSContainer server = new ApacheDSContainer("dc=springframework,dc=org", "classpath:test-server.ldif");
		List<Integer> ports = getDefaultPorts(1);
		server.setPort(ports.get(0));
		server.setLdapOverSslEnabled(true);

		try {
			server.afterPropertiesSet();
			fail("Expected an IllegalArgumentException to be thrown.");
		}
		catch (IllegalArgumentException ex) {
			assertThat(ex).hasMessage("When LdapOverSsl is enabled, the keyStoreFile property must be set.");
		}
	}

	@Test
	public void startWithLdapOverSslWithWrongPassword() throws Exception {
		final ClassPathResource keyStoreResource = new ClassPathResource(
				"/org/springframework/security/ldap/server/spring.keystore");
		final File temporaryKeyStoreFile = new File(this.temporaryFolder.getRoot(), "spring.keystore");
		FileCopyUtils.copy(keyStoreResource.getInputStream(), new FileOutputStream(temporaryKeyStoreFile));

		assertThat(temporaryKeyStoreFile).isFile();

		ApacheDSContainer server = new ApacheDSContainer("dc=springframework,dc=org", "classpath:test-server.ldif");

		List<Integer> ports = getDefaultPorts(1);
		server.setPort(ports.get(0));

		server.setLdapOverSslEnabled(true);
		server.setKeyStoreFile(temporaryKeyStoreFile);
		server.setCertificatePassord("incorrect-password");
		assertThatExceptionOfType(RuntimeException.class).isThrownBy(server::afterPropertiesSet)
				.withMessage("Server startup failed").withRootCauseInstanceOf(UnrecoverableKeyException.class);
	}

	/**
	 * This test starts an LDAP server using LDAPs (LDAP over SSL). A self-signed
	 * certificate is being used, which was previously generated with:
	 *
	 * <pre>
	 * {@code
	 * keytool -genkey -alias spring -keyalg RSA -keystore spring.keystore -validity 3650 -storetype JKS \
	 * -dname "CN=localhost, OU=Spring, O=Pivotal, L=Kailua-Kona, ST=HI, C=US" -keypass spring -storepass spring
	 * }
	 * </pre>
	 * @throws Exception
	 */
	@Test
	public void startWithLdapOverSsl() throws Exception {

		final ClassPathResource keyStoreResource = new ClassPathResource(
				"/org/springframework/security/ldap/server/spring.keystore");
		final File temporaryKeyStoreFile = new File(this.temporaryFolder.getRoot(), "spring.keystore");
		FileCopyUtils.copy(keyStoreResource.getInputStream(), new FileOutputStream(temporaryKeyStoreFile));

		assertThat(temporaryKeyStoreFile).isFile();

		ApacheDSContainer server = new ApacheDSContainer("dc=springframework,dc=org", "classpath:test-server.ldif");

		List<Integer> ports = getDefaultPorts(1);
		server.setPort(ports.get(0));

		server.setLdapOverSslEnabled(true);
		server.setKeyStoreFile(temporaryKeyStoreFile);
		server.setCertificatePassord("spring");

		try {
			server.afterPropertiesSet();
		}
		finally {
			try {
				server.destroy();
			}
			catch (Throwable ex) {
			}
		}
	}

	private List<Integer> getDefaultPorts(int count) throws IOException {
		List<ServerSocket> connections = new ArrayList<>();
		List<Integer> availablePorts = new ArrayList<>(count);
		try {
			for (int i = 0; i < count; i++) {
				ServerSocket socket = new ServerSocket(0);
				connections.add(socket);
				availablePorts.add(socket.getLocalPort());
			}
			return availablePorts;
		}
		finally {
			for (ServerSocket conn : connections) {
				conn.close();
			}
		}
	}

	@Test
	public void afterPropertiesSetWhenPortIsZeroThenRandomPortIsSelected() throws Exception {
		ApacheDSContainer server = new ApacheDSContainer("dc=springframework,dc=org", "classpath:test-server.ldif");
		server.setPort(0);
		try {
			server.afterPropertiesSet();

			assertThat(server.getPort()).isEqualTo(0);
			assertThat(server.getLocalPort()).isNotEqualTo(0);
		}
		finally {
			server.destroy();
		}
	}

}
