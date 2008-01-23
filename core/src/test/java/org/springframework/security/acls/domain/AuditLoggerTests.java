package org.springframework.security.acls.domain;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.Serializable;

import junit.framework.Assert;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.acls.AccessControlEntry;
import org.springframework.security.acls.Acl;
import org.springframework.security.acls.AuditableAccessControlEntry;
import org.springframework.security.acls.Permission;
import org.springframework.security.acls.sid.Sid;

/**
 * Test class for {@link ConsoleAuditLogger}.
 * 
 * @author Andrei Stefan
 */
public class AuditLoggerTests {
	private PrintStream console;

	ByteArrayOutputStream bytes = new ByteArrayOutputStream();

	@Before
	public void onSetUp() {
		console = System.out;
		System.setOut(new PrintStream(bytes));
	}

	@After
	public void onTearDown() {
		System.setOut(console);
	}

	@Test
	public void loggingTests() {
		ConsoleAuditLogger logger = new ConsoleAuditLogger();
		MockAccessControlEntryImpl auditableAccessControlEntry = new MockAccessControlEntryImpl();

		logger.logIfNeeded(true, auditableAccessControlEntry);
		Assert.assertTrue(bytes.size() == 0);

		bytes.reset();
		logger.logIfNeeded(false, auditableAccessControlEntry);
		Assert.assertTrue(bytes.size() == 0);

		auditableAccessControlEntry.setAuditSuccess(true);
		bytes.reset();

		logger.logIfNeeded(true, auditableAccessControlEntry);
		Assert.assertTrue(bytes.toString().length() > 0);
		Assert.assertTrue(bytes.toString().startsWith("GRANTED due to ACE"));

		auditableAccessControlEntry.setAuditFailure(true);
		bytes.reset();

		logger.logIfNeeded(false, auditableAccessControlEntry);
		Assert.assertTrue(bytes.toString().length() > 0);
		Assert.assertTrue(bytes.toString().startsWith("DENIED due to ACE"));

		MockAccessControlEntry accessControlEntry = new MockAccessControlEntry();
		bytes.reset();
		logger.logIfNeeded(true, accessControlEntry);
		Assert.assertTrue(bytes.size() == 0);
	}

	/**
	 * Mock {@link AuditableAccessControlEntry}.
	 */
	private class MockAccessControlEntryImpl implements AuditableAccessControlEntry {
		private boolean auditFailure = false;

		private boolean auditSuccess = false;

		public boolean isAuditFailure() {
			return auditFailure;
		}

		public boolean isAuditSuccess() {
			return auditSuccess;
		}

		public Acl getAcl() {
			return null;
		}

		public Serializable getId() {
			return null;
		}

		public Permission getPermission() {
			return null;
		}

		public Sid getSid() {
			return null;
		}

		public boolean isGranting() {
			return false;
		}

		public void setAuditFailure(boolean auditFailure) {
			this.auditFailure = auditFailure;
		}

		public void setAuditSuccess(boolean auditSuccess) {
			this.auditSuccess = auditSuccess;
		}
	}

	/**
	 * Mock {@link AccessControlEntry}.
	 */
	private class MockAccessControlEntry implements AccessControlEntry {

		public Acl getAcl() {
			return null;
		}

		public Serializable getId() {
			return null;
		}

		public Permission getPermission() {
			return null;
		}

		public Sid getSid() {
			return null;
		}

		public boolean isGranting() {
			return false;
		}

	}
}
