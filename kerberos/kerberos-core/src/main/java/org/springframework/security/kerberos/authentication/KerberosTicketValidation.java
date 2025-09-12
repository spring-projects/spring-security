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

import java.util.HashSet;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;

/**
 * Result of ticket validation
 */
public final class KerberosTicketValidation {

	private final String username;

	private final Subject subject;

	private final byte[] responseToken;

	private final GSSContext gssContext;

	private final GSSCredential delegationCredential;

	public KerberosTicketValidation(String username, String servicePrincipal, byte[] responseToken,
			GSSContext gssContext) {
		this(username, servicePrincipal, responseToken, gssContext, null);
	}

	public KerberosTicketValidation(String username, String servicePrincipal, byte[] responseToken,
			GSSContext gssContext, GSSCredential delegationCredential) {
		final HashSet<KerberosPrincipal> princs = new HashSet<KerberosPrincipal>();
		princs.add(new KerberosPrincipal(servicePrincipal));

		this.username = username;
		this.subject = new Subject(false, princs, new HashSet<Object>(), new HashSet<Object>());
		this.responseToken = responseToken;
		this.gssContext = gssContext;
		this.delegationCredential = delegationCredential;
	}

	public KerberosTicketValidation(String username, Subject subject, byte[] responseToken, GSSContext gssContext) {
		this(username, subject, responseToken, gssContext, null);
	}

	public KerberosTicketValidation(String username, Subject subject, byte[] responseToken, GSSContext gssContext,
			GSSCredential delegationCredential) {
		this.username = username;
		this.subject = subject;
		this.responseToken = responseToken;
		this.gssContext = gssContext;
		this.delegationCredential = delegationCredential;
	}

	public String username() {
		return this.username;
	}

	public byte[] responseToken() {
		return this.responseToken;
	}

	public GSSContext getGssContext() {
		return this.gssContext;
	}

	public Subject subject() {
		return this.subject;
	}

	public GSSCredential getDelegationCredential() {
		return this.delegationCredential;
	}

}
