/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.access.annotation;

import java.util.Collection;

import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.intercept.method.MockMethodInvocation;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Luke Taylor
 * @author Ben Alex
 */
public class Jsr250MethodSecurityMetadataSourceTests {

	Jsr250MethodSecurityMetadataSource mds;

	A a;

	UserAllowedClass userAllowed;

	@BeforeEach
	public void setup() {
		this.mds = new Jsr250MethodSecurityMetadataSource();
		this.a = new A();
		this.userAllowed = new UserAllowedClass();
	}

	private ConfigAttribute[] findAttributes(String methodName) throws Exception {
		return this.mds.findAttributes(this.a.getClass().getMethod(methodName), null).toArray(new ConfigAttribute[0]);
	}

	@Test
	public void methodWithRolesAllowedHasCorrectAttribute() throws Exception {
		ConfigAttribute[] accessAttributes = findAttributes("adminMethod");
		assertThat(accessAttributes).hasSize(1);
		assertThat(accessAttributes[0].toString()).isEqualTo("ROLE_ADMIN");
	}

	@Test
	public void permitAllMethodHasPermitAllAttribute() throws Exception {
		ConfigAttribute[] accessAttributes = findAttributes("permitAllMethod");
		assertThat(accessAttributes).hasSize(1);
		assertThat(accessAttributes[0].toString()).isEqualTo("jakarta.annotation.security.PermitAll");
	}

	@Test
	public void noRoleMethodHasNoAttributes() throws Exception {
		Collection<ConfigAttribute> accessAttributes = this.mds
				.findAttributes(this.a.getClass().getMethod("noRoleMethod"), null);
		assertThat(accessAttributes).isNull();
	}

	@Test
	public void classRoleIsAppliedToNoRoleMethod() throws Exception {
		Collection<ConfigAttribute> accessAttributes = this.mds
				.findAttributes(this.userAllowed.getClass().getMethod("noRoleMethod"), null);
		assertThat(accessAttributes).isNull();
	}

	@Test
	public void methodRoleOverridesClassRole() throws Exception {
		Collection<ConfigAttribute> accessAttributes = this.mds
				.findAttributes(this.userAllowed.getClass().getMethod("adminMethod"), null);
		assertThat(accessAttributes).hasSize(1);
		assertThat(accessAttributes.toArray()[0].toString()).isEqualTo("ROLE_ADMIN");
	}

	@Test
	public void customDefaultRolePrefix() throws Exception {
		this.mds.setDefaultRolePrefix("CUSTOMPREFIX_");
		ConfigAttribute[] accessAttributes = findAttributes("adminMethod");
		assertThat(accessAttributes).hasSize(1);
		assertThat(accessAttributes[0].toString()).isEqualTo("CUSTOMPREFIX_ADMIN");
	}

	@Test
	public void emptyDefaultRolePrefix() throws Exception {
		this.mds.setDefaultRolePrefix("");
		ConfigAttribute[] accessAttributes = findAttributes("adminMethod");
		assertThat(accessAttributes).hasSize(1);
		assertThat(accessAttributes[0].toString()).isEqualTo("ADMIN");
	}

	@Test
	public void nullDefaultRolePrefix() throws Exception {
		this.mds.setDefaultRolePrefix(null);
		ConfigAttribute[] accessAttributes = findAttributes("adminMethod");
		assertThat(accessAttributes).hasSize(1);
		assertThat(accessAttributes[0].toString()).isEqualTo("ADMIN");
	}

	@Test
	public void alreadyHasDefaultPrefix() throws Exception {
		ConfigAttribute[] accessAttributes = findAttributes("roleAdminMethod");
		assertThat(accessAttributes).hasSize(1);
		assertThat(accessAttributes[0].toString()).isEqualTo("ROLE_ADMIN");
	}

	// JSR-250 Spec Tests
	/**
	 * Class-level annotations only affect the class they annotate and their members, that
	 * is, its methods and fields. They never affect a member declared by a superclass,
	 * even if it is not hidden or overridden by the class in question.
	 * @throws Exception
	 */
	@Test
	public void classLevelAnnotationsOnlyAffectTheClassTheyAnnotateAndTheirMembers() throws Exception {
		Child target = new Child();
		MockMethodInvocation mi = new MockMethodInvocation(target, target.getClass(), "notOverriden");
		Collection<ConfigAttribute> accessAttributes = this.mds.getAttributes(mi);
		assertThat(accessAttributes).isNull();
	}

	@Test
	public void classLevelAnnotationsOnlyAffectTheClassTheyAnnotateAndTheirMembersOverriden() throws Exception {
		Child target = new Child();
		MockMethodInvocation mi = new MockMethodInvocation(target, target.getClass(), "overriden");
		Collection<ConfigAttribute> accessAttributes = this.mds.getAttributes(mi);
		assertThat(accessAttributes).hasSize(1);
		assertThat(accessAttributes.toArray()[0].toString()).isEqualTo("ROLE_DERIVED");
	}

	@Test
	public void classLevelAnnotationsImpactMemberLevel() throws Exception {
		Child target = new Child();
		MockMethodInvocation mi = new MockMethodInvocation(target, target.getClass(), "defaults");
		Collection<ConfigAttribute> accessAttributes = this.mds.getAttributes(mi);
		assertThat(accessAttributes).hasSize(1);
		assertThat(accessAttributes.toArray()[0].toString()).isEqualTo("ROLE_DERIVED");
	}

	@Test
	public void classLevelAnnotationsIgnoredByExplicitMemberAnnotation() throws Exception {
		Child target = new Child();
		MockMethodInvocation mi = new MockMethodInvocation(target, target.getClass(), "explicitMethod");
		Collection<ConfigAttribute> accessAttributes = this.mds.getAttributes(mi);
		assertThat(accessAttributes).hasSize(1);
		assertThat(accessAttributes.toArray()[0].toString()).isEqualTo("ROLE_EXPLICIT");
	}

	/**
	 * The interfaces implemented by a class never contribute annotations to the class
	 * itself or any of its members.
	 * @throws Exception
	 */
	@Test
	public void interfacesNeverContributeAnnotationsMethodLevel() throws Exception {
		Parent target = new Parent();
		MockMethodInvocation mi = new MockMethodInvocation(target, target.getClass(), "interfaceMethod");
		Collection<ConfigAttribute> accessAttributes = this.mds.getAttributes(mi);
		assertThat(accessAttributes).isEmpty();
	}

	@Test
	public void interfacesNeverContributeAnnotationsClassLevel() throws Exception {
		Parent target = new Parent();
		MockMethodInvocation mi = new MockMethodInvocation(target, target.getClass(), "notOverriden");
		Collection<ConfigAttribute> accessAttributes = this.mds.getAttributes(mi);
		assertThat(accessAttributes).isEmpty();
	}

	@Test
	public void annotationsOnOverriddenMemberIgnored() throws Exception {
		Child target = new Child();
		MockMethodInvocation mi = new MockMethodInvocation(target, target.getClass(), "overridenIgnored");
		Collection<ConfigAttribute> accessAttributes = this.mds.getAttributes(mi);
		assertThat(accessAttributes).hasSize(1);
		assertThat(accessAttributes.toArray()[0].toString()).isEqualTo("ROLE_DERIVED");
	}

	public static class A {

		public void noRoleMethod() {
		}

		@RolesAllowed("ADMIN")
		public void adminMethod() {
		}

		@RolesAllowed("ROLE_ADMIN")
		public void roleAdminMethod() {
		}

		@PermitAll
		public void permitAllMethod() {
		}

	}

	@RolesAllowed("USER")
	public static class UserAllowedClass {

		public void noRoleMethod() {
		}

		@RolesAllowed("ADMIN")
		public void adminMethod() {
		}

	}

	// JSR-250 Spec
	@RolesAllowed("IPARENT")
	interface IParent {

		@RolesAllowed("INTERFACEMETHOD")
		void interfaceMethod();

	}

	static class Parent implements IParent {

		@Override
		public void interfaceMethod() {
		}

		public void notOverriden() {
		}

		public void overriden() {
		}

		@RolesAllowed("OVERRIDENIGNORED")
		public void overridenIgnored() {
		}

	}

	@RolesAllowed("DERIVED")
	class Child extends Parent {

		@Override
		public void overriden() {
		}

		@Override
		public void overridenIgnored() {
		}

		public void defaults() {
		}

		@RolesAllowed("EXPLICIT")
		public void explicitMethod() {
		}

	}

}
