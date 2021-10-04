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

/**
 * Provides lifecycle services for an embedded LDAP server.
 *
 * @author Eleftheria Stein
 * @since 5.7
 */
public interface EmbeddedLdapServerContainer {

	/**
	 * Returns the embedded LDAP server port.
	 * @return the embedded LDAP server port
	 */
	int getPort();

	/**
	 * The embedded LDAP server port to connect to. Supplying 0 as the port indicates that
	 * a random available port should be selected.
	 * @param port the port to connect to
	 */
	void setPort(int port);

}
