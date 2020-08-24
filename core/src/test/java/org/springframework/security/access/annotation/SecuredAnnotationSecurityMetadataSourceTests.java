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

package org.springframework.security.access.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;

import org.junit.Test;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.annotation.sec2150.MethodInvocationFactory;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.core.GrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests for
 * {@link org.springframework.security.access.annotation.SecuredAnnotationSecurityMetadataSource}
 *
 * @author Mark St.Godard
 * @author Joe Scalise
 * @author Ben Alex
 * @author Luke Taylor
 */
public class SecuredAnnotationSecurityMetadataSourceTests {

	private SecuredAnnotationSecurityMetadataSource mds = new SecuredAnnotationSecurityMetadataSource();

	@Test
	public void genericsSuperclassDeclarationsAreIncludedWhenSubclassesOverride() {
		Method method = null;
		try {
			method = DepartmentServiceImpl.class.getMethod("someUserMethod3", new Class[] { Department.class });
		}
		catch (NoSuchMethodException unexpected) {
			fail("Should be a superMethod called 'someUserMethod3' on class!");
		}
		Collection<ConfigAttribute> attrs = this.mds.findAttributes(method, DepartmentServiceImpl.class);
		assertThat(attrs).isNotNull();
		// expect 1 attribute
		assertThat(attrs.size() == 1).as("Did not find 1 attribute").isTrue();
		// should have 1 SecurityConfig
		for (ConfigAttribute sc : attrs) {
			assertThat(sc.getAttribute()).as("Found an incorrect role").isEqualTo("ROLE_ADMIN");
		}
		Method superMethod = null;
		try {
			superMethod = DepartmentServiceImpl.class.getMethod("someUserMethod3", new Class[] { Entity.class });
		}
		catch (NoSuchMethodException unexpected) {
			fail("Should be a superMethod called 'someUserMethod3' on class!");
		}
		Collection<ConfigAttribute> superAttrs = this.mds.findAttributes(superMethod, DepartmentServiceImpl.class);
		assertThat(superAttrs).isNotNull();
		// This part of the test relates to SEC-274
		// expect 1 attribute
		assertThat(superAttrs).as("Did not find 1 attribute").hasSize(1);
		// should have 1 SecurityConfig
		for (ConfigAttribute sc : superAttrs) {
			assertThat(sc.getAttribute()).as("Found an incorrect role").isEqualTo("ROLE_ADMIN");
		}
	}

	@Test
	public void classLevelAttributesAreFound() {
		Collection<ConfigAttribute> attrs = this.mds.findAttributes(BusinessService.class);
		assertThat(attrs).isNotNull();
		// expect 1 annotation
		assertThat(attrs).hasSize(1);
		// should have 1 SecurityConfig
		SecurityConfig sc = (SecurityConfig) attrs.toArray()[0];
		assertThat(sc.getAttribute()).isEqualTo("ROLE_USER");
	}

	@Test
	public void methodLevelAttributesAreFound() {
		Method method = null;
		try {
			method = BusinessService.class.getMethod("someUserAndAdminMethod", new Class[] {});
		}
		catch (NoSuchMethodException unexpected) {
			fail("Should be a method called 'someUserAndAdminMethod' on class!");
		}
		Collection<ConfigAttribute> attrs = this.mds.findAttributes(method, BusinessService.class);
		// expect 2 attributes
		assertThat(attrs).hasSize(2);
		boolean user = false;
		boolean admin = false;
		// should have 2 SecurityConfigs
		for (ConfigAttribute sc : attrs) {
			assertThat(sc).isInstanceOf(SecurityConfig.class);
			if (sc.getAttribute().equals("ROLE_USER")) {
				user = true;
			}
			else if (sc.getAttribute().equals("ROLE_ADMIN")) {
				admin = true;
			}
		}
		// expect to have ROLE_USER and ROLE_ADMIN
		assertThat(user).isEqualTo(admin).isTrue();
	}

	// SEC-1491
	@Test
	public void customAnnotationAttributesAreFound() {
		SecuredAnnotationSecurityMetadataSource mds = new SecuredAnnotationSecurityMetadataSource(
				new CustomSecurityAnnotationMetadataExtractor());
		Collection<ConfigAttribute> attrs = mds.findAttributes(CustomAnnotatedService.class);
		assertThat(attrs).containsOnly(SecurityEnum.ADMIN);
	}

	@Test
	public void annotatedAnnotationAtClassLevelIsDetected() throws Exception {
		MockMethodInvocation annotatedAtClassLevel = new MockMethodInvocation(new AnnotatedAnnotationAtClassLevel(),
				ReturnVoid.class, "doSomething", List.class);
		ConfigAttribute[] attrs = this.mds.getAttributes(annotatedAtClassLevel).toArray(new ConfigAttribute[0]);
		assertThat(attrs).hasSize(1);
		assertThat(attrs).extracting("attribute").containsOnly("CUSTOM");
	}

	@Test
	public void annotatedAnnotationAtInterfaceLevelIsDetected() throws Exception {
		MockMethodInvocation annotatedAtInterfaceLevel = new MockMethodInvocation(
				new AnnotatedAnnotationAtInterfaceLevel(), ReturnVoid2.class, "doSomething", List.class);
		ConfigAttribute[] attrs = this.mds.getAttributes(annotatedAtInterfaceLevel).toArray(new ConfigAttribute[0]);
		assertThat(attrs).hasSize(1);
		assertThat(attrs).extracting("attribute").containsOnly("CUSTOM");
	}

	@Test
	public void annotatedAnnotationAtMethodLevelIsDetected() throws Exception {
		MockMethodInvocation annotatedAtMethodLevel = new MockMethodInvocation(new AnnotatedAnnotationAtMethodLevel(),
				ReturnVoid.class, "doSomething", List.class);
		ConfigAttribute[] attrs = this.mds.getAttributes(annotatedAtMethodLevel).toArray(new ConfigAttribute[0]);
		assertThat(attrs).hasSize(1);
		assertThat(attrs).extracting("attribute").containsOnly("CUSTOM");
	}

	@Test
	public void proxyFactoryInterfaceAttributesFound() throws Exception {
		MockMethodInvocation mi = MethodInvocationFactory.createSec2150MethodInvocation();
		Collection<ConfigAttribute> attributes = this.mds.getAttributes(mi);
		assertThat(attributes).hasSize(1);
		assertThat(attributes).extracting("attribute").containsOnly("ROLE_PERSON");
	}

	// Inner classes
	class Department extends Entity {

		Department(String name) {
			super(name);
		}

	}

	interface DepartmentService extends BusinessService {

		@Secured({ "ROLE_USER" })
		Department someUserMethod3(Department dept);

	}

	@SuppressWarnings("serial")
	class DepartmentServiceImpl extends BusinessServiceImpl<Department> implements DepartmentService {

		@Override
		@Secured({ "ROLE_ADMIN" })
		public Department someUserMethod3(final Department dept) {
			return super.someUserMethod3(dept);
		}

	}

	// SEC-1491 Related classes. PoC for custom annotation with enum value.
	@CustomSecurityAnnotation(SecurityEnum.ADMIN)
	interface CustomAnnotatedService {

	}

	class CustomAnnotatedServiceImpl implements CustomAnnotatedService {

	}

	enum SecurityEnum implements ConfigAttribute, GrantedAuthority {

		ADMIN, USER;

		@Override
		public String getAttribute() {
			return toString();
		}

		@Override
		public String getAuthority() {
			return toString();
		}

	}

	@Target({ ElementType.METHOD, ElementType.TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	@interface CustomSecurityAnnotation {

		SecurityEnum[] value();

	}

	class CustomSecurityAnnotationMetadataExtractor implements AnnotationMetadataExtractor<CustomSecurityAnnotation> {

		@Override
		public Collection<? extends ConfigAttribute> extractAttributes(CustomSecurityAnnotation securityAnnotation) {
			SecurityEnum[] values = securityAnnotation.value();
			return EnumSet.copyOf(Arrays.asList(values));
		}

	}

	@Target({ ElementType.METHOD, ElementType.TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	@Inherited
	@Secured("CUSTOM")
	public @interface AnnotatedAnnotation {

	}

	public interface ReturnVoid {

		void doSomething(List<?> param);

	}

	@AnnotatedAnnotation
	public interface ReturnVoid2 {

		void doSomething(List<?> param);

	}

	@AnnotatedAnnotation
	public static class AnnotatedAnnotationAtClassLevel implements ReturnVoid {

		@Override
		public void doSomething(List<?> param) {
		}

	}

	public static class AnnotatedAnnotationAtInterfaceLevel implements ReturnVoid2 {

		@Override
		public void doSomething(List<?> param) {
		}

	}

	public static class AnnotatedAnnotationAtMethodLevel implements ReturnVoid {

		@Override
		@AnnotatedAnnotation
		public void doSomething(List<?> param) {
		}

	}

}
