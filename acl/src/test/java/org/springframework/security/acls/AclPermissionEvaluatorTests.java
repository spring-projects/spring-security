package org.springframework.security.acls;

import static org.junit.Assert.*;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.Authentication;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.objectidentity.ObjectIdentityRetrievalStrategy;
import org.springframework.security.acls.sid.Sid;
import org.springframework.security.acls.sid.SidRetrievalStrategy;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class AclPermissionEvaluatorTests {
    Mockery jmock = new JUnit4Mockery();
    Authentication user;
    private AclService service;
    private ObjectIdentityRetrievalStrategy oidStrategy;
    private SidRetrievalStrategy sidStrategy;

    @Before
    public void setup() throws Exception {
        user = jmock.mock(Authentication.class);
        service = jmock.mock(AclService.class);
        oidStrategy = jmock.mock(ObjectIdentityRetrievalStrategy.class);
        sidStrategy = jmock.mock(SidRetrievalStrategy.class);
    }

    @Test
    public void hasPermissionReturnsTrueIfAclGrantsPermission() throws Exception {
        AclPermissionEvaluator pe = new AclPermissionEvaluator(service);
        final Acl acl = jmock.mock(Acl.class);
        pe.setObjectIdentityRetrievalStrategy(oidStrategy);
        pe.setSidRetrievalStrategy(sidStrategy);

        jmock.checking(new Expectations() {{
            ignoring(user);
            ignoring(oidStrategy);
            ignoring(sidStrategy);
            oneOf(service).readAclById(with(any(ObjectIdentity.class)), with(any(Sid[].class)));
                will(returnValue(acl));
            oneOf(acl).isGranted(with(any(Permission[].class)), with(any(Sid[].class)), with(equal(false)));
                will(returnValue(true));
        }});

        assertTrue(pe.hasPermission(user, new Object(), "read"));
    }
}
