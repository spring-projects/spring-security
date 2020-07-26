/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.acls.domain;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.AuditableAccessControlEntry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link ConsoleAuditLogger}.
 *
 * @author Andrei Stefan
 */
public class AuditLoggerTests {

	private PrintStream console;

	private ByteArrayOutputStream bytes = new ByteArrayOutputStream();

	private ConsoleAuditLogger logger;

	private AuditableAccessControlEntry ace;

	@Before
	public void setUp() {
		this.logger = new ConsoleAuditLogger();
		this.ace = mock(AuditableAccessControlEntry.class);
		this.console = System.out;
		System.setOut(new PrintStream(this.bytes));
	}

	@After
	public void tearDown() {
		System.setOut(this.console);
		this.bytes.reset();
	}

	@Test
	public void nonAuditableAceIsIgnored() {
		AccessControlEntry ace = mock(AccessControlEntry.class);
		this.logger.logIfNeeded(true, ace);
		assertThat(this.bytes.size()).isZero();
	}

	@Test
	public void successIsNotLoggedIfAceDoesntRequireSuccessAudit() {
		when(this.ace.isAuditSuccess()).thenReturn(false);
		this.logger.logIfNeeded(true, this.ace);
		assertThat(this.bytes.size()).isZero();
	}

	@Test
	public void successIsLoggedIfAceRequiresSuccessAudit() {
		when(this.ace.isAuditSuccess()).thenReturn(true);

		this.logger.logIfNeeded(true, this.ace);
		assertThat(this.bytes.toString()).startsWith("GRANTED due to ACE");
	}

	@Test
	public void failureIsntLoggedIfAceDoesntRequireFailureAudit() {
		when(this.ace.isAuditFailure()).thenReturn(false);
		this.logger.logIfNeeded(false, this.ace);
		assertThat(this.bytes.size()).isZero();
	}

	@Test
	public void failureIsLoggedIfAceRequiresFailureAudit() {
		when(this.ace.isAuditFailure()).thenReturn(true);
		this.logger.logIfNeeded(false, this.ace);
		assertThat(this.bytes.toString()).startsWith("DENIED due to ACE");
	}

}
