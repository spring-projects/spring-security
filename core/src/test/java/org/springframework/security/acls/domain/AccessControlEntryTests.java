package org.springframework.security.acls.domain;

import junit.framework.Assert;
import junit.framework.TestCase;

import org.springframework.security.acls.AccessControlEntry;
import org.springframework.security.acls.Acl;
import org.springframework.security.acls.AuditableAccessControlEntry;
import org.springframework.security.acls.NotFoundException;
import org.springframework.security.acls.Permission;
import org.springframework.security.acls.UnloadedSidException;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.sid.PrincipalSid;
import org.springframework.security.acls.sid.Sid;

/**
 * Test class for {@link AccessControlEntryImpl}
 * 
 * @author Andrei Stefan
 */
public class AccessControlEntryTests extends TestCase {
	
	//~ Methods ========================================================================================================
	
	public void testConstructorRequiredFields() {
		// Check Acl field is present
		try {
			AccessControlEntry ace = new AccessControlEntryImpl(null, null, new PrincipalSid("johndoe"),
					BasePermission.ADMINISTRATION, true, true, true);
			Assert.fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			Assert.assertTrue(true);
		}

		// Check Sid field is present
		try {
			AccessControlEntry ace = new AccessControlEntryImpl(null, new MockAcl(), null,
					BasePermission.ADMINISTRATION, true, true, true);
			Assert.fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			Assert.assertTrue(true);
		}

		// Check Permission field is present
		try {
			AccessControlEntry ace = new AccessControlEntryImpl(null, new MockAcl(), new PrincipalSid("johndoe"), null,
					true, true, true);
			Assert.fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			Assert.assertTrue(true);
		}
	}

	public void testAccessControlEntryImplGetters() {
		Acl mockAcl = new MockAcl();
		Sid sid = new PrincipalSid("johndoe");

		// Create a sample entry
		AccessControlEntry ace = new AccessControlEntryImpl(new Long(1), mockAcl, sid, BasePermission.ADMINISTRATION,
				true, true, true);

		// and check every get() method
		Assert.assertEquals(new Long(1), ace.getId());
		Assert.assertEquals(mockAcl, ace.getAcl());
		Assert.assertEquals(sid, ace.getSid());
		Assert.assertTrue(ace.isGranting());
		Assert.assertEquals(BasePermission.ADMINISTRATION, ace.getPermission());
		Assert.assertTrue(((AuditableAccessControlEntry) ace).isAuditFailure());
		Assert.assertTrue(((AuditableAccessControlEntry) ace).isAuditSuccess());
	}

	public void testEquals() {
		Acl mockAcl = new MockAcl();
		Sid sid = new PrincipalSid("johndoe");

		AccessControlEntry ace = new AccessControlEntryImpl(new Long(1), mockAcl, sid, BasePermission.ADMINISTRATION,
				true, true, true);

		Assert.assertFalse(ace.equals(null));
		Assert.assertFalse(ace.equals(new Long(100)));
		Assert.assertTrue(ace.equals(ace));
		Assert.assertTrue(ace.equals(new AccessControlEntryImpl(new Long(1), mockAcl, sid,
				BasePermission.ADMINISTRATION, true, true, true)));
		Assert.assertFalse(ace.equals(new AccessControlEntryImpl(new Long(2), mockAcl, sid,
				BasePermission.ADMINISTRATION, true, true, true)));
		Assert.assertFalse(ace.equals(new AccessControlEntryImpl(new Long(1), new MockAcl(), sid,
				BasePermission.ADMINISTRATION, true, true, true)));
		Assert.assertFalse(ace.equals(new AccessControlEntryImpl(new Long(1), mockAcl, new PrincipalSid("scott"),
				BasePermission.ADMINISTRATION, true, true, true)));
		Assert.assertFalse(ace.equals(new AccessControlEntryImpl(new Long(1), mockAcl, sid, BasePermission.WRITE, true,
				true, true)));
		Assert.assertFalse(ace.equals(new AccessControlEntryImpl(new Long(1), mockAcl, sid,
				BasePermission.ADMINISTRATION, false, true, true)));
		Assert.assertFalse(ace.equals(new AccessControlEntryImpl(new Long(1), mockAcl, sid,
				BasePermission.ADMINISTRATION, true, false, true)));
		Assert.assertFalse(ace.equals(new AccessControlEntryImpl(new Long(1), mockAcl, sid,
				BasePermission.ADMINISTRATION, true, true, false)));
	}

	//~ Inner Classes ==================================================================================================
	
	private class MockAcl implements Acl {

		public AccessControlEntry[] getEntries() {
			return null;
		}

		public ObjectIdentity getObjectIdentity() {
			return null;
		}

		public Sid getOwner() {
			return null;
		}

		public Acl getParentAcl() {
			return null;
		}

		public boolean isEntriesInheriting() {
			return false;
		}

		public boolean isGranted(Permission[] permission, Sid[] sids, boolean administrativeMode)
				throws NotFoundException, UnloadedSidException {
			return false;
		}

		public boolean isSidLoaded(Sid[] sids) {
			return false;
		}

	}

}
