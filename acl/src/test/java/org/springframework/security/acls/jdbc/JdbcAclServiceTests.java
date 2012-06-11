package org.springframework.security.acls.jdbc;

import static org.mockito.Matchers.anyListOf;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;

@RunWith(MockitoJUnitRunner.class)
public class JdbcAclServiceTests {
    @Mock
    private DataSource dataSource;

    @Mock
    private LookupStrategy lookupStrategy;

    private JdbcAclService aclService;

    @Before
    public void setUp() {
        aclService = new JdbcAclService(dataSource, lookupStrategy);
    }

    // SEC-1898
    @Test(expected = NotFoundException.class)
    public void readAclByIdMissingAcl() {
        Map<ObjectIdentity, Acl> result = new HashMap<ObjectIdentity, Acl>();
        when(lookupStrategy.readAclsById(anyListOf(ObjectIdentity.class), anyListOf(Sid.class))).thenReturn(result);
        ObjectIdentity objectIdentity = new ObjectIdentityImpl(Object.class, 1);
        List<Sid> sids = Arrays.<Sid> asList(new PrincipalSid("user"));

        aclService.readAclById(objectIdentity, sids);
    }
}