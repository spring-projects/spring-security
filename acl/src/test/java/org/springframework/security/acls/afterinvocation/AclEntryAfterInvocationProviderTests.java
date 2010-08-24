package org.springframework.security.acls.afterinvocation;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import org.junit.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.acls.model.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * @author Luke Taylor
 */
@SuppressWarnings({"unchecked"})
public class AclEntryAfterInvocationProviderTests {

    @Test(expected=IllegalArgumentException.class)
    public void rejectsMissingPermissions() throws Exception {
        try {
            new AclEntryAfterInvocationProvider(mock(AclService.class), null);
            fail("Exception expected");
        } catch (IllegalArgumentException expected) {
        }
        new AclEntryAfterInvocationProvider(mock(AclService.class), Collections.<Permission>emptyList());
    }

    @Test
    public void accessIsAllowedIfPermissionIsGranted() {
        AclService service = mock(AclService.class);
        Acl acl = mock(Acl.class);
        when(acl.isGranted(any(List.class), any(List.class), anyBoolean())).thenReturn(true);
        when(service.readAclById(any(ObjectIdentity.class), any(List.class))).thenReturn(acl);
        AclEntryAfterInvocationProvider provider = new AclEntryAfterInvocationProvider(service, Arrays.asList(mock(Permission.class)));
        provider.setMessageSource(new SpringSecurityMessageSource());
        provider.setObjectIdentityRetrievalStrategy(mock(ObjectIdentityRetrievalStrategy.class));
        provider.setProcessDomainObjectClass(Object.class);
        provider.setSidRetrievalStrategy(mock(SidRetrievalStrategy.class));
        Object returned = new Object();

        assertSame(returned, provider.decide(mock(Authentication.class), new Object(), SecurityConfig.createList("AFTER_ACL_READ"), returned));
    }

    @Test
    public void accessIsGrantedIfNoAttributesDefined() throws Exception {
        AclEntryAfterInvocationProvider provider = new AclEntryAfterInvocationProvider(mock(AclService.class), Arrays.asList(mock(Permission.class)));
        Object returned = new Object();

        assertSame(returned, provider.decide(mock(Authentication.class), new Object(), Collections.<ConfigAttribute>emptyList(), returned));
    }

    @Test
    public void accessIsGrantedIfObjectTypeNotSupported() throws Exception {
        AclEntryAfterInvocationProvider provider = new AclEntryAfterInvocationProvider(mock(AclService.class), Arrays.asList(mock(Permission.class)));
        provider.setProcessDomainObjectClass(String.class);
        // Not a String
        Object returned = new Object();

        assertSame(returned, provider.decide(mock(Authentication.class), new Object(), SecurityConfig.createList("AFTER_ACL_READ"), returned));
    }


    @Test(expected= AccessDeniedException.class)
    public void accessIsDeniedIfPermissionIsNotGranted() {
        AclService service = mock(AclService.class);
        Acl acl = mock(Acl.class);
        when(acl.isGranted(any(List.class), any(List.class), anyBoolean())).thenReturn(false);
        // Try a second time with no permissions found
        when(acl.isGranted(any(List.class), any(List.class), anyBoolean())).thenThrow(new NotFoundException(""));
        when(service.readAclById(any(ObjectIdentity.class), any(List.class))).thenReturn(acl);
        AclEntryAfterInvocationProvider provider = new AclEntryAfterInvocationProvider(service, Arrays.asList(mock(Permission.class)));
        provider.setProcessConfigAttribute("MY_ATTRIBUTE");
        provider.setMessageSource(new SpringSecurityMessageSource());
        provider.setObjectIdentityRetrievalStrategy(mock(ObjectIdentityRetrievalStrategy.class));
        provider.setProcessDomainObjectClass(Object.class);
        provider.setSidRetrievalStrategy(mock(SidRetrievalStrategy.class));
        try {
            provider.decide(mock(Authentication.class), new Object(), SecurityConfig.createList("UNSUPPORTED", "MY_ATTRIBUTE"), new Object());
            fail();
        } catch (AccessDeniedException expected) {
        }
        // Second scenario with no acls found
        provider.decide(mock(Authentication.class), new Object(), SecurityConfig.createList("UNSUPPORTED", "MY_ATTRIBUTE"), new Object());
    }

    @Test
    public void nullReturnObjectIsIgnored() throws Exception {
        AclService service = mock(AclService.class);
        AclEntryAfterInvocationProvider provider = new AclEntryAfterInvocationProvider(service, Arrays.asList(mock(Permission.class)));

        assertNull(provider.decide(mock(Authentication.class), new Object(), SecurityConfig.createList("AFTER_ACL_COLLECTION_READ"), null));
        verify(service, never()).readAclById(any(ObjectIdentity.class), any(List.class));
    }
}
