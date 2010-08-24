package org.springframework.security.acls.afterinvocation;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.acls.model.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * @author Luke Taylor
 */
@SuppressWarnings({"unchecked"})
public class AclEntryAfterInvocationCollectionFilteringProviderTests {
    @Test
    public void objectsAreRemovedIfPermissionDenied() throws Exception {
        AclService service = mock(AclService.class);
        Acl acl = mock(Acl.class);
        when(acl.isGranted(any(List.class), any(List.class), anyBoolean())).thenReturn(false);
        when(service.readAclById(any(ObjectIdentity.class), any(List.class))).thenReturn(acl);
        AclEntryAfterInvocationCollectionFilteringProvider provider = new AclEntryAfterInvocationCollectionFilteringProvider(service, Arrays.asList(mock(Permission.class)));
        provider.setObjectIdentityRetrievalStrategy(mock(ObjectIdentityRetrievalStrategy.class));
        provider.setProcessDomainObjectClass(Object.class);
        provider.setSidRetrievalStrategy(mock(SidRetrievalStrategy.class));

        Object returned = provider.decide(mock(Authentication.class), new Object(), SecurityConfig.createList("AFTER_ACL_COLLECTION_READ"), new ArrayList(Arrays.asList(new Object(), new Object())));
        assertTrue(returned instanceof List);
        assertTrue(((List)returned).isEmpty());
        returned = provider.decide(mock(Authentication.class), new Object(), SecurityConfig.createList("UNSUPPORTED", "AFTER_ACL_COLLECTION_READ"), new Object[] {new Object(), new Object()});
        assertTrue(returned instanceof Object[]);
        assertTrue(((Object[])returned).length == 0);
    }

    @Test
    public void accessIsGrantedIfNoAttributesDefined() throws Exception {
        AclEntryAfterInvocationCollectionFilteringProvider provider = new AclEntryAfterInvocationCollectionFilteringProvider(mock(AclService.class), Arrays.asList(mock(Permission.class)));
        Object returned = new Object();

        assertSame(returned, provider.decide(mock(Authentication.class), new Object(), Collections.<ConfigAttribute>emptyList(), returned));
    }

    @Test
    public void nullReturnObjectIsIgnored() throws Exception {
        AclService service = mock(AclService.class);
        AclEntryAfterInvocationCollectionFilteringProvider provider = new AclEntryAfterInvocationCollectionFilteringProvider(service, Arrays.asList(mock(Permission.class)));

        assertNull(provider.decide(mock(Authentication.class), new Object(), SecurityConfig.createList("AFTER_ACL_COLLECTION_READ"), null));
        verify(service, never()).readAclById(any(ObjectIdentity.class), any(List.class));
    }

}
