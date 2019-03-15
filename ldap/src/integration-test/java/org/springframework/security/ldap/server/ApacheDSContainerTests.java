/*
 * Copyright 2002-2013 the original author or authors.
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

import static org.assertj.core.api.Assertions.fail;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

/**
 * Useful for debugging the container by itself.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.0
 */
public class ApacheDSContainerTests {

	// SEC-2162
	@Test
	public void failsToStartThrowsException() throws Exception {
		ApacheDSContainer server1 = new ApacheDSContainer("dc=springframework,dc=org",
				"classpath:test-server.ldif");
		ApacheDSContainer server2 = new ApacheDSContainer("dc=springframework,dc=org",
				"classpath:missing.ldif");
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
			catch (Throwable t) {
			}
			try {
				server2.destroy();
			}
			catch (Throwable t) {
			}
		}
	}

	// SEC-2161
	@Test
	public void multipleInstancesSimultanciously() throws Exception {
		ApacheDSContainer server1 = new ApacheDSContainer("dc=springframework,dc=org",
				"classpath:test-server.ldif");
		ApacheDSContainer server2 = new ApacheDSContainer("dc=springframework,dc=org",
				"classpath:test-server.ldif");
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
			catch (Throwable t) {
			}
			try {
				server2.destroy();
			}
			catch (Throwable t) {
			}
		}
	}

	private List<Integer> getDefaultPorts(int count) throws IOException {
		List<ServerSocket> connections = new ArrayList<ServerSocket>();
		List<Integer> availablePorts = new ArrayList<Integer>(count);
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
}
