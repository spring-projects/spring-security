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
package org.springframework.security.acls.domain;

import static org.assertj.core.api.Assertions.*;
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

	// ~ Methods
	// ========================================================================================================

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
			new AccessControlEntryImpl(null, mock(Acl.class),
					new PrincipalSid("johndoe"), null, true, true, true);
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
		AccessControlEntry ace = new AccessControlEntryImpl(Long.valueOf(1), mockAcl,
				sid, BasePermission.ADMINISTRATION, true, true, true);

		// and check every get() method
		assertThat(ace.getId()).isEqualTo(new Long(1));
		assertThat(ace.getAcl()).isEqualTo(mockAcl);
		assertThat(ace.getSid()).isEqualTo(sid);
		assertThat(ace.isGranting()).isTrue();
		assertThat(ace.getPermission()).isEqualTo(BasePermission.ADMINISTRATION);
		assertThat(((AuditableAccessControlEntry) ace).isAuditFailure()).isTrue();
		assertThat(((AuditableAccessControlEntry) ace).isAuditSuccess()).isTrue();
	}

	@Test
	public void testEquals() {
		final Acl mockAcl = mock(Acl.class);
		final ObjectIdentity oid = mock(ObjectIdentity.class);

		when(mockAcl.getObjectIdentity()).thenReturn(oid);
		Sid sid = new PrincipalSid("johndoe");

		AccessControlEntry ace = new AccessControlEntryImpl(Long.valueOf(1), mockAcl,
				sid, BasePermission.ADMINISTRATION, true, true, true);

		assertThat(ace).isNotNull();
		assertThat(ace).isNotEqualTo(Long.valueOf(100));
		assertThat(ace).isEqualTo(ace);
		assertThat(ace).isEqualTo(new AccessControlEntryImpl(Long.valueOf(1), mockAcl, sid,
				BasePermission.ADMINISTRATION, true, true, true));
		assertThat(ace).isNotEqualTo(new AccessControlEntryImpl(Long.valueOf(2), mockAcl, sid,
				BasePermission.ADMINISTRATION, true, true, true));
		assertThat(ace).isNotEqualTo(new AccessControlEntryImpl(Long.valueOf(1), mockAcl,
				new PrincipalSid("scott"), BasePermission.ADMINISTRATION, true, true,
				true));
		assertThat(ace).isNotEqualTo(new AccessControlEntryImpl(Long.valueOf(1), mockAcl, sid,
				BasePermission.WRITE, true, true, true));
		assertThat(ace).isNotEqualTo(new AccessControlEntryImpl(Long.valueOf(1), mockAcl, sid,
				BasePermission.ADMINISTRATION, false, true, true));
		assertThat(ace).isNotEqualTo(new AccessControlEntryImpl(Long.valueOf(1), mockAcl, sid,
				BasePermission.ADMINISTRATION, true, false, true));
		assertThat(ace).isNotEqualTo(new AccessControlEntryImpl(Long.valueOf(1), mockAcl, sid,
				BasePermission.ADMINISTRATION, true, true, false));
	}
}
