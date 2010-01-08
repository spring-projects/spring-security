package org.springframework.security.acls;

import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

import org.junit.Test;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.core.Authentication;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class AclPermissionEvaluatorTests {

    @Test
    @SuppressWarnings("unchecked")
    public void hasPermissionReturnsTrueIfAclGrantsPermission() throws Exception {
        AclService service = mock(AclService.class);
        AclPermissionEvaluator pe = new AclPermissionEvaluator(service);
        ObjectIdentity oid = mock(ObjectIdentity.class);
        ObjectIdentityRetrievalStrategy oidStrategy = mock(ObjectIdentityRetrievalStrategy.class);
        when(oidStrategy.getObjectIdentity(anyObject())).thenReturn(oid);
        pe.setObjectIdentityRetrievalStrategy(oidStrategy);
        pe.setSidRetrievalStrategy(mock(SidRetrievalStrategy.class));
        Acl acl = mock(Acl.class);

        when(service.readAclById(any(ObjectIdentity.class), anyList())).thenReturn(acl);
        when(acl.isGranted(anyList(), anyList(), eq(false))).thenReturn(true);

        assertTrue(pe.hasPermission(mock(Authentication.class), new Object(), "READ"));
    }
}
