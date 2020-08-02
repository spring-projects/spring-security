/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.acls.afterinvocation;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Test;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * @author Luke Taylor
 */
@SuppressWarnings({ "unchecked" })
public class AclEntryAfterInvocationProviderTests {

	@Test(expected = IllegalArgumentException.class)
	public void rejectsMissingPermissions() {
		try {
			new AclEntryAfterInvocationProvider(mock(AclService.class), null);
			fail("Exception expected");
		}
		catch (IllegalArgumentException expected) {
		}
		new AclEntryAfterInvocationProvider(mock(AclService.class), Collections.<Permission>emptyList());
	}

	@Test
	public void accessIsAllowedIfPermissionIsGranted() {
		AclService service = mock(AclService.class);
		Acl acl = mock(Acl.class);
		given(acl.isGranted(any(List.class), any(List.class), anyBoolean())).willReturn(true);
		given(service.readAclById(any(), any())).willReturn(acl);
		AclEntryAfterInvocationProvider provider = new AclEntryAfterInvocationProvider(service,
				Arrays.asList(mock(Permission.class)));
		provider.setMessageSource(new SpringSecurityMessageSource());
		provider.setObjectIdentityRetrievalStrategy(mock(ObjectIdentityRetrievalStrategy.class));
		provider.setProcessDomainObjectClass(Object.class);
		provider.setSidRetrievalStrategy(mock(SidRetrievalStrategy.class));
		Object returned = new Object();
		assertThat(returned).isSameAs(provider.decide(mock(Authentication.class), new Object(),
				SecurityConfig.createList("AFTER_ACL_READ"), returned));
	}

	@Test
	public void accessIsGrantedIfNoAttributesDefined() {
		AclEntryAfterInvocationProvider provider = new AclEntryAfterInvocationProvider(mock(AclService.class),
				Arrays.asList(mock(Permission.class)));
		Object returned = new Object();
		assertThat(returned).isSameAs(provider.decide(mock(Authentication.class), new Object(),
				Collections.<ConfigAttribute>emptyList(), returned));
	}

	@Test
	public void accessIsGrantedIfObjectTypeNotSupported() {
		AclEntryAfterInvocationProvider provider = new AclEntryAfterInvocationProvider(mock(AclService.class),
				Arrays.asList(mock(Permission.class)));
		provider.setProcessDomainObjectClass(String.class);
		// Not a String
		Object returned = new Object();
		assertThat(returned).isSameAs(provider.decide(mock(Authentication.class), new Object(),
				SecurityConfig.createList("AFTER_ACL_READ"), returned));
	}

	@Test(expected = AccessDeniedException.class)
	public void accessIsDeniedIfPermissionIsNotGranted() {
		AclService service = mock(AclService.class);
		Acl acl = mock(Acl.class);
		given(acl.isGranted(any(List.class), any(List.class), anyBoolean())).willReturn(false);
		// Try a second time with no permissions found
		given(acl.isGranted(any(), any(List.class), anyBoolean())).willThrow(new NotFoundException(""));
		given(service.readAclById(any(), any())).willReturn(acl);
		AclEntryAfterInvocationProvider provider = new AclEntryAfterInvocationProvider(service,
				Arrays.asList(mock(Permission.class)));
		provider.setProcessConfigAttribute("MY_ATTRIBUTE");
		provider.setMessageSource(new SpringSecurityMessageSource());
		provider.setObjectIdentityRetrievalStrategy(mock(ObjectIdentityRetrievalStrategy.class));
		provider.setProcessDomainObjectClass(Object.class);
		provider.setSidRetrievalStrategy(mock(SidRetrievalStrategy.class));
		try {
			provider.decide(mock(Authentication.class), new Object(),
					SecurityConfig.createList("UNSUPPORTED", "MY_ATTRIBUTE"), new Object());
			fail("Expected Exception");
		}
		catch (AccessDeniedException expected) {
		}
		// Second scenario with no acls found
		provider.decide(mock(Authentication.class), new Object(),
				SecurityConfig.createList("UNSUPPORTED", "MY_ATTRIBUTE"), new Object());
	}

	@Test
	public void nullReturnObjectIsIgnored() {
		AclService service = mock(AclService.class);
		AclEntryAfterInvocationProvider provider = new AclEntryAfterInvocationProvider(service,
				Arrays.asList(mock(Permission.class)));
		assertThat(provider.decide(mock(Authentication.class), new Object(),
				SecurityConfig.createList("AFTER_ACL_COLLECTION_READ"), null)).isNull();
		verify(service, never()).readAclById(any(ObjectIdentity.class), any(List.class));
	}

}
