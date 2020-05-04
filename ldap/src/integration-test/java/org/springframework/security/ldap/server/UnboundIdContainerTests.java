/*
 * Copyright 2002-2018 the original author or authors.
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

import java.io.IOException;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import org.springframework.context.support.GenericApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Eddú Meléndez
 */
public class UnboundIdContainerTests {

	private final String validLdifClassPath =  "classpath:test-server.ldif";
	private final String validRootDn =  "dc=springframework,dc=org";

	@Test
	public void startLdapServer() throws Exception {
		UnboundIdContainer server = new UnboundIdContainer(validLdifClassPath,
				validRootDn);
		server.setApplicationContext(new GenericApplicationContext());
		List<Integer> ports = getDefaultPorts(1);
		server.setPort(ports.get(0));

		try {
			server.afterPropertiesSet();
			assertThat(server.getPort()).isEqualTo(ports.get(0));
		} finally {
			server.destroy();
		}
	}


	@Test
	public void afterPropertiesSetWhenPortIsZeroThenRandomPortIsSelected() throws Exception {
		UnboundIdContainer server = new UnboundIdContainer(validLdifClassPath, validRootDn);
		server.setPort(0);

		try {
			server.afterPropertiesSet();
			assertThat(server.getPort()).isNotEqualTo(0);
		} finally {
			server.destroy();
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
		} finally {
			for (ServerSocket conn : connections) {
				conn.close();
			}
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidLdapFile(){
		UnboundIdContainer server = new UnboundIdContainer(validRootDn, "classpath:missing-file.ldif");
		server.setPort(0);
		try {
			server.start();

		}catch (Exception e){} finally {
			server.destroy();
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidNullLdapFile(){
		new UnboundIdContainer(validRootDn, null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidEmptyPathLdapFile(){
		new UnboundIdContainer(validRootDn, "");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidRootDnLdapFile(){
		UnboundIdContainer server = new UnboundIdContainer("dc=fake,dc=org", validLdifClassPath);
		server.setPort(0);
		try {
			server.start();

		}catch (Exception e){} finally {
			server.destroy();
		}
	}

}
