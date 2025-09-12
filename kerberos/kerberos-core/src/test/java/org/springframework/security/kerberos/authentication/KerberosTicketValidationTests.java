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

import javax.security.auth.Subject;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class KerberosTicketValidationTests {

	private String username = "username";

	private Subject subject = new Subject();

	private byte[] responseToken = "token".getBytes();

	private GSSContext gssContext = mock(GSSContext.class);

	private GSSCredential delegationCredential = mock(GSSCredential.class);

	@Test
	public void createResultOfTicketValidationWithSubject() {

		KerberosTicketValidation ticketValidation = new KerberosTicketValidation(this.username, this.subject,
				this.responseToken, this.gssContext);

		assertThat(ticketValidation.username()).isEqualTo(this.username);
		assertThat(ticketValidation.responseToken()).isEqualTo(this.responseToken);
		assertThat(ticketValidation.getGssContext()).isEqualTo(this.gssContext);

		assertThat(ticketValidation.getDelegationCredential()).withFailMessage("With no credential delegation")
			.isNull();
	}

	@Test
	public void createResultOfTicketValidationWithSubjectAndDelegation() {

		KerberosTicketValidation ticketValidation = new KerberosTicketValidation(this.username, this.subject,
				this.responseToken, this.gssContext, this.delegationCredential);

		assertThat(ticketValidation.username()).isEqualTo(this.username);
		assertThat(ticketValidation.responseToken()).isEqualTo(this.responseToken);
		assertThat(ticketValidation.getGssContext()).isEqualTo(this.gssContext);

		assertThat(ticketValidation.getDelegationCredential()).withFailMessage("With credential delegation")
			.isEqualTo(this.delegationCredential);
	}

}
