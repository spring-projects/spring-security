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

package org.springframework.security.kerberos.authentication;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;

import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosClient;

/**
 * <p>
 * Holds the Subject of the currently authenticated user, since this Jaas object also has
 * the credentials, and permits creating new credentials against other Kerberos services.
 * </p>
 *
 * @author Bogdan Mustiata
 * @see SunJaasKerberosClient
 * @see org.springframework.security.kerberos.authentication.KerberosAuthenticationProvider
 */
public class JaasSubjectHolder implements Serializable {

	private static final long serialVersionUID = 8174713761131577405L;

	private Subject jaasSubject;

	private String username;

	private Map<String, byte[]> savedTokens = new HashMap<String, byte[]>();

	public JaasSubjectHolder(Subject jaasSubject) {
		this.jaasSubject = jaasSubject;
	}

	public JaasSubjectHolder(Subject jaasSubject, String username) {
		this.jaasSubject = jaasSubject;
		this.username = username;
	}

	public String getUsername() {
		return this.username;
	}

	public Subject getJaasSubject() {
		return this.jaasSubject;
	}

	public void addToken(String targetService, byte[] outToken) {
		this.savedTokens.put(targetService, outToken);
	}

	public byte[] getToken(String principalName) {
		return this.savedTokens.get(principalName);
	}

}
