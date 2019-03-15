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
package org.springframework.security.acls;

import static org.mockito.Mockito.*;

import org.junit.Test;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.core.Authentication;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * @author Luke Taylor
 */
@SuppressWarnings({ "unchecked" })
public class AclPermissionCacheOptimizerTests {

	@Test
	public void eagerlyLoadsRequiredAcls() throws Exception {
		AclService service = mock(AclService.class);
		AclPermissionCacheOptimizer pco = new AclPermissionCacheOptimizer(service);
		ObjectIdentityRetrievalStrategy oidStrat = mock(ObjectIdentityRetrievalStrategy.class);
		SidRetrievalStrategy sidStrat = mock(SidRetrievalStrategy.class);
		pco.setObjectIdentityRetrievalStrategy(oidStrat);
		pco.setSidRetrievalStrategy(sidStrat);
		Object[] dos = { new Object(), null, new Object() };
		ObjectIdentity[] oids = { new ObjectIdentityImpl("A", "1"),
				new ObjectIdentityImpl("A", "2") };
		when(oidStrat.getObjectIdentity(dos[0])).thenReturn(oids[0]);
		when(oidStrat.getObjectIdentity(dos[2])).thenReturn(oids[1]);

		pco.cachePermissionsFor(mock(Authentication.class), Arrays.asList(dos));

		// AclService should be invoked with the list of required Oids
		verify(service).readAclsById(eq(Arrays.asList(oids)), any(List.class));
	}

	@Test
	public void ignoresEmptyCollection() {
		AclService service = mock(AclService.class);
		AclPermissionCacheOptimizer pco = new AclPermissionCacheOptimizer(service);
		ObjectIdentityRetrievalStrategy oids = mock(ObjectIdentityRetrievalStrategy.class);
		SidRetrievalStrategy sids = mock(SidRetrievalStrategy.class);
		pco.setObjectIdentityRetrievalStrategy(oids);
		pco.setSidRetrievalStrategy(sids);

		pco.cachePermissionsFor(mock(Authentication.class), Collections.emptyList());

		verifyZeroInteractions(service, sids, oids);
	}

}
