package org.springframework.security.acls.expression;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.*;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.acls.Acl;
import org.springframework.security.acls.AclService;
import org.springframework.security.acls.expression.AclPermissionEvaluator;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.objectidentity.ObjectIdentityRetrievalStrategy;
import org.springframework.security.acls.sid.SidRetrievalStrategy;
import org.springframework.security.core.Authentication;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class AclPermissionEvaluatorTests {
    Authentication user;
    private AclService service;
    private ObjectIdentityRetrievalStrategy oidStrategy;
    private SidRetrievalStrategy sidStrategy;

    @Before
    public void setup() throws Exception {
        user = mock(Authentication.class);
        service = mock(AclService.class);
        oidStrategy = mock(ObjectIdentityRetrievalStrategy.class);
        sidStrategy = mock(SidRetrievalStrategy.class);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void hasPermissionReturnsTrueIfAclGrantsPermission() throws Exception {
        AclPermissionEvaluator pe = new AclPermissionEvaluator(service);
        final Acl acl = mock(Acl.class);
        pe.setObjectIdentityRetrievalStrategy(oidStrategy);
        pe.setSidRetrievalStrategy(sidStrategy);

        when(service.readAclById(any(ObjectIdentity.class), any(List.class))).thenReturn(acl);
        when(acl.isGranted(any(List.class), any(List.class), false)).thenReturn(true);

        assertTrue(pe.hasPermission(user, new Object(), "READ"));
    }
}
