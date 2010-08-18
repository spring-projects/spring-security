package org.springframework.security.acls.domain;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.junit.Test;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AuditableAccessControlEntry;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;

/**
 * Tests for {@link AccessControlEntryImpl}.
 *
 * @author Andrei Stefan
 */
public class AccessControlImplEntryTests {

    //~ Methods ========================================================================================================

    @Test
    public void testConstructorRequiredFields() {
        // Check Acl field is present
        try {
            new AccessControlEntryImpl(null, null, new PrincipalSid("johndoe"),
                    BasePermission.ADMINISTRATION, true, true, true);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }

        // Check Sid field is present
        try {
            new AccessControlEntryImpl(null, mock(Acl.class), null,
                    BasePermission.ADMINISTRATION, true, true, true);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }

        // Check Permission field is present
        try {
            new AccessControlEntryImpl(null, mock(Acl.class), new PrincipalSid("johndoe"), null,
                    true, true, true);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testAccessControlEntryImplGetters() {
        Acl mockAcl = mock(Acl.class);
        Sid sid = new PrincipalSid("johndoe");

        // Create a sample entry
        AccessControlEntry ace = new AccessControlEntryImpl(Long.valueOf(1), mockAcl, sid, BasePermission.ADMINISTRATION,
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
        final Acl mockAcl = mock(Acl.class);
        final ObjectIdentity oid = mock(ObjectIdentity.class);

        when(mockAcl.getObjectIdentity()).thenReturn(oid);
        Sid sid = new PrincipalSid("johndoe");

        AccessControlEntry ace = new AccessControlEntryImpl(Long.valueOf(1), mockAcl, sid, BasePermission.ADMINISTRATION,
                true, true, true);

        assertFalse(ace.equals(null));
        assertFalse(ace.equals(Long.valueOf(100)));
        assertTrue(ace.equals(ace));
        assertTrue(ace.equals(new AccessControlEntryImpl(Long.valueOf(1), mockAcl, sid,
                BasePermission.ADMINISTRATION, true, true, true)));
        assertFalse(ace.equals(new AccessControlEntryImpl(Long.valueOf(2), mockAcl, sid,
                BasePermission.ADMINISTRATION, true, true, true)));
        assertFalse(ace.equals(new AccessControlEntryImpl(Long.valueOf(1), mockAcl, new PrincipalSid("scott"),
                BasePermission.ADMINISTRATION, true, true, true)));
        assertFalse(ace.equals(new AccessControlEntryImpl(Long.valueOf(1), mockAcl, sid, BasePermission.WRITE, true,
                true, true)));
        assertFalse(ace.equals(new AccessControlEntryImpl(Long.valueOf(1), mockAcl, sid,
                BasePermission.ADMINISTRATION, false, true, true)));
        assertFalse(ace.equals(new AccessControlEntryImpl(Long.valueOf(1), mockAcl, sid,
                BasePermission.ADMINISTRATION, true, false, true)));
        assertFalse(ace.equals(new AccessControlEntryImpl(Long.valueOf(1), mockAcl, sid,
                BasePermission.ADMINISTRATION, true, true, false)));
    }
}
