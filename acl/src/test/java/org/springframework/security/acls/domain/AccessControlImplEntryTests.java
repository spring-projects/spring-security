package org.springframework.security.acls.domain;

import static org.junit.Assert.*;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.junit.Test;
import org.springframework.security.acls.AccessControlEntry;
import org.springframework.security.acls.Acl;
import org.springframework.security.acls.AuditableAccessControlEntry;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.sid.PrincipalSid;
import org.springframework.security.acls.sid.Sid;

/**
 * Tests for {@link AccessControlEntryImpl}.
 *
 * @author Andrei Stefan
 * @version $Id$
 */
public class AccessControlImplEntryTests {
    Mockery jmock = new JUnit4Mockery();

    //~ Methods ========================================================================================================

    @Test
    public void testConstructorRequiredFields() {
        // Check Acl field is present
        try {
            AccessControlEntry ace = new AccessControlEntryImpl(null, null, new PrincipalSid("johndoe"),
                    BasePermission.ADMINISTRATION, true, true, true);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }

        // Check Sid field is present
        try {
            AccessControlEntry ace = new AccessControlEntryImpl(null, jmock.mock(Acl.class), null,
                    BasePermission.ADMINISTRATION, true, true, true);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }

        // Check Permission field is present
        try {
            AccessControlEntry ace = new AccessControlEntryImpl(null, jmock.mock(Acl.class), new PrincipalSid("johndoe"), null,
                    true, true, true);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testAccessControlEntryImplGetters() {
        Acl mockAcl = jmock.mock(Acl.class);
        Sid sid = new PrincipalSid("johndoe");

        // Create a sample entry
        AccessControlEntry ace = new AccessControlEntryImpl(new Long(1), mockAcl, sid, BasePermission.ADMINISTRATION,
                true, true, true);

        // and check every get() method
        assertEquals(new Long(1), ace.getId());
        assertEquals(mockAcl, ace.getAcl());
        assertEquals(sid, ace.getSid());
        assertTrue(ace.isGranting());
        assertEquals(BasePermission.ADMINISTRATION, ace.getPermission());
        assertTrue(((AuditableAccessControlEntry) ace).isAuditFailure());
        assertTrue(((AuditableAccessControlEntry) ace).isAuditSuccess());
    }

    @Test
    public void testEquals() {
        final Acl mockAcl = jmock.mock(Acl.class);
        final ObjectIdentity oid = jmock.mock(ObjectIdentity.class);
        jmock.checking(new Expectations() {{
            allowing(mockAcl).getObjectIdentity(); will(returnValue(oid));
        }});
        Sid sid = new PrincipalSid("johndoe");

        AccessControlEntry ace = new AccessControlEntryImpl(new Long(1), mockAcl, sid, BasePermission.ADMINISTRATION,
                true, true, true);

        assertFalse(ace.equals(null));
        assertFalse(ace.equals(new Long(100)));
        assertTrue(ace.equals(ace));
        assertTrue(ace.equals(new AccessControlEntryImpl(new Long(1), mockAcl, sid,
                BasePermission.ADMINISTRATION, true, true, true)));
        assertFalse(ace.equals(new AccessControlEntryImpl(new Long(2), mockAcl, sid,
                BasePermission.ADMINISTRATION, true, true, true)));
        assertFalse(ace.equals(new AccessControlEntryImpl(new Long(1), mockAcl, new PrincipalSid("scott"),
                BasePermission.ADMINISTRATION, true, true, true)));
        assertFalse(ace.equals(new AccessControlEntryImpl(new Long(1), mockAcl, sid, BasePermission.WRITE, true,
                true, true)));
        assertFalse(ace.equals(new AccessControlEntryImpl(new Long(1), mockAcl, sid,
                BasePermission.ADMINISTRATION, false, true, true)));
        assertFalse(ace.equals(new AccessControlEntryImpl(new Long(1), mockAcl, sid,
                BasePermission.ADMINISTRATION, true, false, true)));
        assertFalse(ace.equals(new AccessControlEntryImpl(new Long(1), mockAcl, sid,
                BasePermission.ADMINISTRATION, true, true, false)));
    }
}
