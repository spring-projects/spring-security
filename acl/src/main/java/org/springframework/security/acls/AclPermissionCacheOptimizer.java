/*
 * Copyright 2004-present the original author or authors.
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

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;

import org.springframework.core.log.LogMessage;
import org.springframework.security.access.PermissionCacheOptimizer;
import org.springframework.security.acls.domain.ObjectIdentityRetrievalStrategyImpl;
import org.springframework.security.acls.domain.SidRetrievalStrategyImpl;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * Batch loads ACLs for collections of objects to allow optimised filtering.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public class AclPermissionCacheOptimizer implements PermissionCacheOptimizer {

private final Log logger = LogFactory.getLog(getClass());

private final AclService aclService;

private SidRetrievalStrategy sidRetrievalStrategy = new SidRetrievalStrategyImpl();

private ObjectIdentityRetrievalStrategy oidRetrievalStrategy = new ObjectIdentityRetrievalStrategyImpl();

private @Nullable AclCache aclCache;

public AclPermissionCacheOptimizer(AclService aclService) {
Assert.notNull(aclService, "AclService required");
this.aclService = aclService;
}

public AclPermissionCacheOptimizer(AclService aclService, @Nullable AclCache aclCache) {
Assert.notNull(aclService, "AclService required");
this.aclService = aclService;
this.aclCache = aclCache;
}

@Override
public void cachePermissionsFor(Authentication authentication, Collection<?> objects) {
if (objects.isEmpty()) {
return;
}
Set<ObjectIdentity> oidsToCache = new LinkedHashSet<>(objects.size());
for (Object domainObject : objects) {
extractObjectIdentities(domainObject, oidsToCache);
}
if (this.aclCache != null) {
oidsToCache.removeIf((oid) -> this.aclCache.getFromCache(oid) != null);
}
if (oidsToCache.isEmpty()) {
return;
}
List<Sid> sids = this.sidRetrievalStrategy.getSids(authentication);
this.logger.debug(LogMessage.of(() -> "Eagerly loading Acls for " + oidsToCache.size() + " objects"));
try {
this.aclService.readAclsById(new ArrayList<>(oidsToCache), sids);
}
catch (NotFoundException notFound) {
this.logger.debug(LogMessage.format("Some ACLs were not found: %s", notFound.getMessage()));
}
}

private void extractObjectIdentities(@Nullable Object domainObject, Set<ObjectIdentity> oidsToCache) {
if (domainObject == null) {
return;
}
if (domainObject instanceof Map.Entry<?, ?> entry) {
if (entry.getValue() != null) {
extractObjectIdentities(entry.getValue(), oidsToCache);
}
if (entry.getKey() != null) {
extractObjectIdentities(entry.getKey(), oidsToCache);
}
return;
}
try {
ObjectIdentity oid = this.oidRetrievalStrategy.getObjectIdentity(domainObject);
if (oid != null) {
oidsToCache.add(oid);
}
}
catch (Exception ex) {
this.logger.trace(LogMessage.format("Could not extract ObjectIdentity from %s: %s", domainObject, ex.getMessage()));
}
}

public void setObjectIdentityRetrievalStrategy(ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy) {
Assert.notNull(objectIdentityRetrievalStrategy, "ObjectIdentityRetrievalStrategy required");
this.oidRetrievalStrategy = objectIdentityRetrievalStrategy;
}

public void setSidRetrievalStrategy(SidRetrievalStrategy sidRetrievalStrategy) {
Assert.notNull(sidRetrievalStrategy, "SidRetrievalStrategy required");
this.sidRetrievalStrategy = sidRetrievalStrategy;
}

public void setAclCache(@Nullable AclCache aclCache) {
this.aclCache = aclCache;
}

}
