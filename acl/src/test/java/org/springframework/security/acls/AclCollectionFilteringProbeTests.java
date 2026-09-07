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

import java.io.Serializable;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

class AclCollectionFilteringProbeTests {

private TestAclCache aclCache;

private CountingAclService countingAclService;

private AclPermissionEvaluator permissionEvaluator;

private AclPermissionCacheOptimizer permissionCacheOptimizer;

private DefaultMethodSecurityExpressionHandler expressionHandler;

private Authentication authentication;

private SpelExpressionParser parser;

private MethodInvocation invocation;

@BeforeEach
void setUp() throws Exception {
this.aclCache = new TestAclCache();
this.countingAclService = new CountingAclService(this.aclCache);
this.permissionEvaluator = new AclPermissionEvaluator(this.countingAclService);
this.permissionCacheOptimizer = new AclPermissionCacheOptimizer(this.countingAclService, this.aclCache);

ObjectIdentityRetrievalStrategy oidStrategy = (domainObject) -> {
if (domainObject instanceof TestEntity entity) {
return new ObjectIdentityImpl(TestEntity.class, entity.getId());
}
return new ObjectIdentityImpl(domainObject);
};
this.permissionEvaluator.setObjectIdentityRetrievalStrategy(oidStrategy);
this.permissionCacheOptimizer.setObjectIdentityRetrievalStrategy(oidStrategy);

this.expressionHandler = new DefaultMethodSecurityExpressionHandler();
this.expressionHandler.setPermissionEvaluator(this.permissionEvaluator);
this.expressionHandler.setPermissionCacheOptimizer(this.permissionCacheOptimizer);

this.authentication = new TestingAuthenticationToken("user", "password");
this.parser = new SpelExpressionParser();

this.invocation = mock(MethodInvocation.class);
Method method = TestEntity.class.getDeclaredMethod("getId");
given(this.invocation.getMethod()).willReturn(method);
given(this.invocation.getThis()).willReturn(new TestEntity(1L));
given(this.invocation.getArguments()).willReturn(new Object[0]);
}

@Test
void probeCase1_CollectionFilteringMustIssueBoundedLookups() {
List<TestEntity> entities = new ArrayList<>();
for (long i = 1; i <= 20; i++) {
entities.add(new TestEntity(i));
}

EvaluationContext ctx = this.expressionHandler.createEvaluationContext(this.authentication, this.invocation);
Expression expr = this.parser.parseExpression("hasPermission(filterObject, 'READ')");
this.expressionHandler.filter(entities, expr, ctx);

assertThat(this.countingAclService.getDatabaseLookupCount())
.as("Collection filtering should execute in bounded lookups (<= 2), but issued %s lookups",
this.countingAclService.getDatabaseLookupCount())
.isLessThanOrEqualTo(2);
}

@Test
void probeCase2_MapFilteringMustIssueBoundedLookups() {
Map<String, TestEntity> map = new LinkedHashMap<>();
for (long i = 1; i <= 20; i++) {
map.put("key" + i, new TestEntity(i));
}

EvaluationContext ctx = this.expressionHandler.createEvaluationContext(this.authentication, this.invocation);
Expression expr = this.parser.parseExpression("hasPermission(filterObject.value, 'READ')");
this.expressionHandler.filter(map, expr, ctx);

assertThat(this.countingAclService.getDatabaseLookupCount())
.as("Map filtering should execute in bounded lookups (<= 2), but issued %s lookups",
this.countingAclService.getDatabaseLookupCount())
.isLessThanOrEqualTo(2);
}

@Test
void probeCase3_DeltaCachingMustOnlyQueryColdItems() {
for (long i = 1; i <= 10; i++) {
this.countingAclService.preload(new ObjectIdentityImpl(TestEntity.class, i));
}
this.countingAclService.resetCounter();

List<TestEntity> entities = new ArrayList<>();
for (long i = 1; i <= 20; i++) {
entities.add(new TestEntity(i));
}

EvaluationContext ctx = this.expressionHandler.createEvaluationContext(this.authentication, this.invocation);
Expression expr = this.parser.parseExpression("hasPermission(filterObject, 'READ')");
this.expressionHandler.filter(entities, expr, ctx);

assertThat(this.countingAclService.getQueriedIdentitiesCount())
.as("Delta caching should only query the 10 uncached items, but queried %s",
this.countingAclService.getQueriedIdentitiesCount())
.isEqualTo(10);
}

@Test
void probeCase4_FullyWarmCacheMustIssueZeroLookups() {
for (long i = 1; i <= 20; i++) {
this.countingAclService.preload(new ObjectIdentityImpl(TestEntity.class, i));
}
this.countingAclService.resetCounter();

List<TestEntity> entities = new ArrayList<>();
for (long i = 1; i <= 20; i++) {
entities.add(new TestEntity(i));
}

EvaluationContext ctx = this.expressionHandler.createEvaluationContext(this.authentication, this.invocation);
Expression expr = this.parser.parseExpression("hasPermission(filterObject, 'READ')");
this.expressionHandler.filter(entities, expr, ctx);

assertThat(this.countingAclService.getDatabaseLookupCount())
.as("Fully warm cache should issue 0 lookups, but was %s",
this.countingAclService.getDatabaseLookupCount())
.isEqualTo(0);
}

static class TestEntity {

private final Long id;

TestEntity(Long id) {
this.id = id;
}

Long getId() {
return this.id;
}

}

private static class TestAclCache implements AclCache {

private final Map<ObjectIdentity, MutableAcl> cache = new ConcurrentHashMap<>();

@Override
public void evictFromCache(Serializable pk) {
}

@Override
public void evictFromCache(ObjectIdentity objectIdentity) {
this.cache.remove(objectIdentity);
}

@Override
public MutableAcl getFromCache(ObjectIdentity objectIdentity) {
return this.cache.get(objectIdentity);
}

@Override
public MutableAcl getFromCache(Serializable pk) {
return null;
}

@Override
public void putInCache(MutableAcl acl) {
this.cache.put(acl.getObjectIdentity(), acl);
}

@Override
public void clearCache() {
this.cache.clear();
}

}

private static class CountingAclService implements AclService {

private final AtomicInteger databaseLookupCount = new AtomicInteger(0);
private final AtomicInteger queriedIdentitiesCount = new AtomicInteger(0);
private final TestAclCache cache;

CountingAclService(TestAclCache cache) {
this.cache = cache;
}

int getDatabaseLookupCount() {
return this.databaseLookupCount.get();
}

int getQueriedIdentitiesCount() {
return this.queriedIdentitiesCount.get();
}

void resetCounter() {
this.databaseLookupCount.set(0);
this.queriedIdentitiesCount.set(0);
}

void preload(ObjectIdentity oid) {
MutableAcl acl = mock(MutableAcl.class);
given(acl.getObjectIdentity()).willReturn(oid);
given(acl.isGranted(any(), any(), any(Boolean.class))).willReturn(true);
this.cache.putInCache(acl);
}

@Override
public List<ObjectIdentity> findChildren(ObjectIdentity parentIdentity) {
return Collections.emptyList();
}

@Override
public Acl readAclById(ObjectIdentity object) throws NotFoundException {
Acl cached = this.cache.getFromCache(object);
if (cached != null) {
return cached;
}
this.databaseLookupCount.incrementAndGet();
this.queriedIdentitiesCount.incrementAndGet();
MutableAcl acl = mock(MutableAcl.class);
given(acl.getObjectIdentity()).willReturn(object);
given(acl.isGranted(any(), any(), any(Boolean.class))).willReturn(true);
this.cache.putInCache(acl);
return acl;
}

@Override
public Acl readAclById(ObjectIdentity object, List<Sid> sids) throws NotFoundException {
return readAclById(object);
}

@Override
public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects) throws NotFoundException {
List<ObjectIdentity> missing = new ArrayList<>();
Map<ObjectIdentity, Acl> result = new LinkedHashMap<>();
for (ObjectIdentity oid : objects) {
Acl acl = this.cache.getFromCache(oid);
if (acl != null) {
result.put(oid, acl);
}
else {
missing.add(oid);
}
}
if (!missing.isEmpty()) {
this.databaseLookupCount.incrementAndGet();
this.queriedIdentitiesCount.addAndGet(missing.size());
for (ObjectIdentity oid : missing) {
MutableAcl acl = mock(MutableAcl.class);
given(acl.getObjectIdentity()).willReturn(oid);
given(acl.isGranted(any(), any(), any(Boolean.class))).willReturn(true);
this.cache.putInCache(acl);
result.put(oid, acl);
}
}
return result;
}

@Override
public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects, List<Sid> sids) throws NotFoundException {
return readAclsById(objects);
}

}

}
