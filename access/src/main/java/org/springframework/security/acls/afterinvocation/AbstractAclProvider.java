/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import java.util.List;

import org.springframework.security.access.AfterInvocationProvider;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.security.acls.domain.ObjectIdentityRetrievalStrategyImpl;
import org.springframework.security.acls.domain.SidRetrievalStrategyImpl;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

/**
 * Abstract {@link AfterInvocationProvider} which provides commonly-used ACL-related
 * services.
 *
 * @author Ben Alex
 * @deprecated please use {@link AclPermissionEvaluator} instead. Spring Method Security
 * annotations may also prove useful, for example
 * {@code @PostAuthorize("hasPermission(filterObject, read)")}
 */
@Deprecated
public abstract class AbstractAclProvider implements AfterInvocationProvider {

	protected final AclService aclService;

	protected String processConfigAttribute;

	protected Class<?> processDomainObjectClass = Object.class;

	protected ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy = new ObjectIdentityRetrievalStrategyImpl();

	protected SidRetrievalStrategy sidRetrievalStrategy = new SidRetrievalStrategyImpl();

	protected final List<Permission> requirePermission;

	public AbstractAclProvider(AclService aclService, String processConfigAttribute,
			List<Permission> requirePermission) {
		Assert.hasText(processConfigAttribute, "A processConfigAttribute is mandatory");
		Assert.notNull(aclService, "An AclService is mandatory");
		Assert.isTrue(!ObjectUtils.isEmpty(requirePermission), "One or more requirePermission entries is mandatory");
		this.aclService = aclService;
		this.processConfigAttribute = processConfigAttribute;
		this.requirePermission = requirePermission;
	}

	protected Class<?> getProcessDomainObjectClass() {
		return this.processDomainObjectClass;
	}

	protected boolean hasPermission(Authentication authentication, Object domainObject) {
		// Obtain the OID applicable to the domain object
		ObjectIdentity objectIdentity = this.objectIdentityRetrievalStrategy.getObjectIdentity(domainObject);

		// Obtain the SIDs applicable to the principal
		List<Sid> sids = this.sidRetrievalStrategy.getSids(authentication);

		try {
			// Lookup only ACLs for SIDs we're interested in
			Acl acl = this.aclService.readAclById(objectIdentity, sids);
			return acl.isGranted(this.requirePermission, sids, false);
		}
		catch (NotFoundException ex) {
			return false;
		}
	}

	public void setObjectIdentityRetrievalStrategy(ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy) {
		Assert.notNull(objectIdentityRetrievalStrategy, "ObjectIdentityRetrievalStrategy required");
		this.objectIdentityRetrievalStrategy = objectIdentityRetrievalStrategy;
	}

	protected void setProcessConfigAttribute(String processConfigAttribute) {
		Assert.hasText(processConfigAttribute, "A processConfigAttribute is mandatory");
		this.processConfigAttribute = processConfigAttribute;
	}

	public void setProcessDomainObjectClass(Class<?> processDomainObjectClass) {
		Assert.notNull(processDomainObjectClass, "processDomainObjectClass cannot be set to null");
		this.processDomainObjectClass = processDomainObjectClass;
	}

	public void setSidRetrievalStrategy(SidRetrievalStrategy sidRetrievalStrategy) {
		Assert.notNull(sidRetrievalStrategy, "SidRetrievalStrategy required");
		this.sidRetrievalStrategy = sidRetrievalStrategy;
	}

	@Override
	public boolean supports(ConfigAttribute attribute) {
		return this.processConfigAttribute.equals(attribute.getAttribute());
	}

	/**
	 * This implementation supports any type of class, because it does not query the
	 * presented secure object.
	 * @param clazz the secure object
	 * @return always <code>true</code>
	 */
	@Override
	public boolean supports(Class<?> clazz) {
		return true;
	}

}
