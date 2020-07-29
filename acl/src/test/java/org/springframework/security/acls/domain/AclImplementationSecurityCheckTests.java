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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.fail;

/**
 * Test class for {@link AclAuthorizationStrategyImpl} and {@link AclImpl} security
 * checks.
 *
 * @author Andrei Stefan
 */
public class AclImplementationSecurityCheckTests {

	private static final String TARGET_CLASS = "org.springframework.security.acls.TargetObject";

	@Before
	public void setUp() {
		SecurityContextHolder.clearContext();
	}

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testSecurityCheckNoACEs() {
		Authentication auth = new TestingAuthenticationToken("user", "password", "ROLE_GENERAL", "ROLE_AUDITING",
				"ROLE_OWNERSHIP");
		auth.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(auth);

		ObjectIdentity identity = new ObjectIdentityImpl(TARGET_CLASS, 100L);
		AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(
				new SimpleGrantedAuthority("ROLE_OWNERSHIP"), new SimpleGrantedAuthority("ROLE_AUDITING"),
				new SimpleGrantedAuthority("ROLE_GENERAL"));

		Acl acl = new AclImpl(identity, 1L, aclAuthorizationStrategy, new ConsoleAuditLogger());

		aclAuthorizationStrategy.securityCheck(acl, AclAuthorizationStrategy.CHANGE_GENERAL);
		aclAuthorizationStrategy.securityCheck(acl, AclAuthorizationStrategy.CHANGE_AUDITING);
		aclAuthorizationStrategy.securityCheck(acl, AclAuthorizationStrategy.CHANGE_OWNERSHIP);

		// Create another authorization strategy
		AclAuthorizationStrategy aclAuthorizationStrategy2 = new AclAuthorizationStrategyImpl(
				new SimpleGrantedAuthority("ROLE_ONE"), new SimpleGrantedAuthority("ROLE_TWO"),
				new SimpleGrantedAuthority("ROLE_THREE"));
		Acl acl2 = new AclImpl(identity, 1L, aclAuthorizationStrategy2, new ConsoleAuditLogger());
		// Check access in case the principal has no authorization rights
		try {
			aclAuthorizationStrategy2.securityCheck(acl2, AclAuthorizationStrategy.CHANGE_GENERAL);
			fail("It should have thrown NotFoundException");
		}
		catch (NotFoundException expected) {
		}
		try {
			aclAuthorizationStrategy2.securityCheck(acl2, AclAuthorizationStrategy.CHANGE_AUDITING);
			fail("It should have thrown NotFoundException");
		}
		catch (NotFoundException expected) {
		}
		try {
			aclAuthorizationStrategy2.securityCheck(acl2, AclAuthorizationStrategy.CHANGE_OWNERSHIP);
			fail("It should have thrown NotFoundException");
		}
		catch (NotFoundException expected) {
		}
	}

	@Test
	public void testSecurityCheckWithMultipleACEs() {
		// Create a simple authentication with ROLE_GENERAL
		Authentication auth = new TestingAuthenticationToken("user", "password", "ROLE_GENERAL");
		auth.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(auth);

		ObjectIdentity identity = new ObjectIdentityImpl(TARGET_CLASS, 100L);
		// Authorization strategy will require a different role for each access
		AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(
				new SimpleGrantedAuthority("ROLE_OWNERSHIP"), new SimpleGrantedAuthority("ROLE_AUDITING"),
				new SimpleGrantedAuthority("ROLE_GENERAL"));

		// Let's give the principal the ADMINISTRATION permission, without
		// granting access
		MutableAcl aclFirstDeny = new AclImpl(identity, 1L, aclAuthorizationStrategy, new ConsoleAuditLogger());
		aclFirstDeny.insertAce(0, BasePermission.ADMINISTRATION, new PrincipalSid(auth), false);

		// The CHANGE_GENERAL test should pass as the principal has ROLE_GENERAL
		aclAuthorizationStrategy.securityCheck(aclFirstDeny, AclAuthorizationStrategy.CHANGE_GENERAL);

		// The CHANGE_AUDITING and CHANGE_OWNERSHIP should fail since the
		// principal doesn't have these authorities,
		// nor granting access
		try {
			aclAuthorizationStrategy.securityCheck(aclFirstDeny, AclAuthorizationStrategy.CHANGE_AUDITING);
			fail("It should have thrown AccessDeniedException");
		}
		catch (AccessDeniedException expected) {
		}
		try {
			aclAuthorizationStrategy.securityCheck(aclFirstDeny, AclAuthorizationStrategy.CHANGE_OWNERSHIP);
			fail("It should have thrown AccessDeniedException");
		}
		catch (AccessDeniedException expected) {
		}

		// Add granting access to this principal
		aclFirstDeny.insertAce(1, BasePermission.ADMINISTRATION, new PrincipalSid(auth), true);
		// and try again for CHANGE_AUDITING - the first ACE's granting flag
		// (false) will deny this access
		try {
			aclAuthorizationStrategy.securityCheck(aclFirstDeny, AclAuthorizationStrategy.CHANGE_AUDITING);
			fail("It should have thrown AccessDeniedException");
		}
		catch (AccessDeniedException expected) {
		}

		// Create another ACL and give the principal the ADMINISTRATION
		// permission, with granting access
		MutableAcl aclFirstAllow = new AclImpl(identity, 1L, aclAuthorizationStrategy, new ConsoleAuditLogger());
		aclFirstAllow.insertAce(0, BasePermission.ADMINISTRATION, new PrincipalSid(auth), true);

		// The CHANGE_AUDITING test should pass as there is one ACE with
		// granting access

		aclAuthorizationStrategy.securityCheck(aclFirstAllow, AclAuthorizationStrategy.CHANGE_AUDITING);

		// Add a deny ACE and test again for CHANGE_AUDITING
		aclFirstAllow.insertAce(1, BasePermission.ADMINISTRATION, new PrincipalSid(auth), false);
		try {
			aclAuthorizationStrategy.securityCheck(aclFirstAllow, AclAuthorizationStrategy.CHANGE_AUDITING);

		}
		catch (AccessDeniedException notExpected) {
			fail("It shouldn't have thrown AccessDeniedException");
		}

		// Create an ACL with no ACE
		MutableAcl aclNoACE = new AclImpl(identity, 1L, aclAuthorizationStrategy, new ConsoleAuditLogger());
		try {
			aclAuthorizationStrategy.securityCheck(aclNoACE, AclAuthorizationStrategy.CHANGE_AUDITING);
			fail("It should have thrown NotFoundException");
		}
		catch (NotFoundException expected) {

		}
		// and still grant access for CHANGE_GENERAL
		try {
			aclAuthorizationStrategy.securityCheck(aclNoACE, AclAuthorizationStrategy.CHANGE_GENERAL);

		}
		catch (NotFoundException expected) {
			fail("It shouldn't have thrown NotFoundException");
		}
	}

	@Test
	public void testSecurityCheckWithInheritableACEs() {
		// Create a simple authentication with ROLE_GENERAL
		Authentication auth = new TestingAuthenticationToken("user", "password", "ROLE_GENERAL");
		auth.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(auth);

		ObjectIdentity identity = new ObjectIdentityImpl(TARGET_CLASS, 100);
		// Authorization strategy will require a different role for each access
		AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(
				new SimpleGrantedAuthority("ROLE_ONE"), new SimpleGrantedAuthority("ROLE_TWO"),
				new SimpleGrantedAuthority("ROLE_GENERAL"));

		// Let's give the principal an ADMINISTRATION permission, with granting
		// access
		MutableAcl parentAcl = new AclImpl(identity, 1, aclAuthorizationStrategy, new ConsoleAuditLogger());
		parentAcl.insertAce(0, BasePermission.ADMINISTRATION, new PrincipalSid(auth), true);
		MutableAcl childAcl = new AclImpl(identity, 2, aclAuthorizationStrategy, new ConsoleAuditLogger());

		// Check against the 'child' acl, which doesn't offer any authorization
		// rights on CHANGE_OWNERSHIP
		try {
			aclAuthorizationStrategy.securityCheck(childAcl, AclAuthorizationStrategy.CHANGE_OWNERSHIP);
			fail("It should have thrown NotFoundException");
		}
		catch (NotFoundException expected) {

		}

		// Link the child with its parent and test again against the
		// CHANGE_OWNERSHIP right
		childAcl.setParent(parentAcl);
		childAcl.setEntriesInheriting(true);
		try {
			aclAuthorizationStrategy.securityCheck(childAcl, AclAuthorizationStrategy.CHANGE_OWNERSHIP);

		}
		catch (NotFoundException expected) {
			fail("It shouldn't have thrown NotFoundException");
		}

		// Create a root parent and link it to the middle parent
		MutableAcl rootParentAcl = new AclImpl(identity, 1, aclAuthorizationStrategy, new ConsoleAuditLogger());
		parentAcl = new AclImpl(identity, 1, aclAuthorizationStrategy, new ConsoleAuditLogger());
		rootParentAcl.insertAce(0, BasePermission.ADMINISTRATION, new PrincipalSid(auth), true);
		parentAcl.setEntriesInheriting(true);
		parentAcl.setParent(rootParentAcl);
		childAcl.setParent(parentAcl);
		try {
			aclAuthorizationStrategy.securityCheck(childAcl, AclAuthorizationStrategy.CHANGE_OWNERSHIP);

		}
		catch (NotFoundException expected) {
			fail("It shouldn't have thrown NotFoundException");
		}
	}

	@Test
	public void testSecurityCheckPrincipalOwner() {
		Authentication auth = new TestingAuthenticationToken("user", "password", "ROLE_ONE");
		auth.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(auth);

		ObjectIdentity identity = new ObjectIdentityImpl(TARGET_CLASS, 100);
		AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(
				new SimpleGrantedAuthority("ROLE_OWNERSHIP"), new SimpleGrantedAuthority("ROLE_AUDITING"),
				new SimpleGrantedAuthority("ROLE_GENERAL"));

		Acl acl = new AclImpl(identity, 1, aclAuthorizationStrategy,
				new DefaultPermissionGrantingStrategy(new ConsoleAuditLogger()), null, null, false,
				new PrincipalSid(auth));
		try {
			aclAuthorizationStrategy.securityCheck(acl, AclAuthorizationStrategy.CHANGE_GENERAL);
		}
		catch (AccessDeniedException notExpected) {
			fail("It shouldn't have thrown AccessDeniedException");
		}
		try {
			aclAuthorizationStrategy.securityCheck(acl, AclAuthorizationStrategy.CHANGE_AUDITING);
			fail("It shouldn't have thrown AccessDeniedException");
		}
		catch (NotFoundException expected) {
		}
		try {
			aclAuthorizationStrategy.securityCheck(acl, AclAuthorizationStrategy.CHANGE_OWNERSHIP);
		}
		catch (AccessDeniedException notExpected) {
			fail("It shouldn't have thrown AccessDeniedException");
		}
	}

}
