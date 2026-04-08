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

import java.security.PrivilegedAction;

import javax.security.auth.Subject;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;

/**
 * <p>
 * Allows creating tickets against other service principals storing the tickets in the
 * KerberosAuthentication's JaasSubjectHolder.
 * </p>
 *
 * @author Bogdan Mustiata
 */
public final class KerberosMultiTier {

	public static final String KERBEROS_OID_STRING = "1.2.840.113554.1.2.2";

	public static final Oid KERBEROS_OID = createOid(KERBEROS_OID_STRING);

	/**
	 * Create a new ticket for the
	 * @param authentication
	 * @param username
	 * @param lifetimeInSeconds
	 * @param targetService
	 * @return
	 */
	public static Authentication authenticateService(Authentication authentication, final String username,
			final int lifetimeInSeconds, final String targetService) {

		KerberosAuthentication kerberosAuthentication = (KerberosAuthentication) authentication;
		final JaasSubjectHolder jaasSubjectHolder = kerberosAuthentication.getJaasSubjectHolder();
		Subject subject = jaasSubjectHolder.getJaasSubject();

		Subject.doAs(subject, new PrivilegedAction<@Nullable Object>() {
			@Override
			public @Nullable Object run() {
				runAuthentication(jaasSubjectHolder, username, lifetimeInSeconds, targetService);

				return null;
			}
		});

		return authentication;
	}

	public static byte @Nullable [] getTokenForService(Authentication authentication, String principalName) {
		KerberosAuthentication kerberosAuthentication = (KerberosAuthentication) authentication;
		final JaasSubjectHolder jaasSubjectHolder = kerberosAuthentication.getJaasSubjectHolder();

		return jaasSubjectHolder.getToken(principalName);
	}

	private static void runAuthentication(JaasSubjectHolder jaasContext, String username, int lifetimeInSeconds,
			String targetService) {
		try {
			GSSManager manager = GSSManager.getInstance();
			GSSName clientName = manager.createName(username, GSSName.NT_USER_NAME);

			GSSCredential clientCredential = manager.createCredential(clientName, lifetimeInSeconds, KERBEROS_OID,
					GSSCredential.INITIATE_ONLY);

			GSSName serverName = manager.createName(targetService, GSSName.NT_USER_NAME);

			GSSContext securityContext = manager.createContext(serverName, KERBEROS_OID, clientCredential,
					GSSContext.DEFAULT_LIFETIME);

			securityContext.requestCredDeleg(true);
			securityContext.requestInteg(false);
			securityContext.requestAnonymity(false);
			securityContext.requestMutualAuth(false);
			securityContext.requestReplayDet(false);
			securityContext.requestSequenceDet(false);

			boolean established = false;

			byte[] outToken = new byte[0];

			while (!established) {
				byte[] inToken = new byte[0];
				outToken = securityContext.initSecContext(inToken, 0, inToken.length);

				established = securityContext.isEstablished();
			}

			jaasContext.addToken(targetService, outToken);
		}
		catch (Exception ex) {
			throw new BadCredentialsException("Kerberos authentication failed", ex);
		}
	}

	private static Oid createOid(String oid) {
		try {
			return new Oid(oid);
		}
		catch (GSSException ex) {
			throw new IllegalStateException("Unable to instantiate Oid: ", ex);
		}
	}

	private KerberosMultiTier() {
	}

}
