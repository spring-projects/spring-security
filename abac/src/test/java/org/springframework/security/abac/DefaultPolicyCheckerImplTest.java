/*
 * Copyright 2017-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.abac;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.security.abac.json.JsonFilePolicyServiceImpl;
import org.springframework.security.abac.model.PolicyService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Renato Soppelsa
 * @since 5.0
 */
@RunWith(JUnit4.class)
public class DefaultPolicyCheckerImplTest {

	private static DefaultPolicyCheckerImpl policyChecker;
	private static List<? extends GrantedAuthority> authorities;

	@BeforeClass
	public static void beforeClass() {
		authorities = Arrays.asList(new SimpleGrantedAuthority("ADMIN"));
		PolicyService policyService = new JsonFilePolicyServiceImpl("policy.abac.json");
		policyChecker = new DefaultPolicyCheckerImpl(policyService);
	}

	@Test
	public void policyApplies() {
		class TEST {
			int age = 21;

			public int getAge() {
				return age;
			}
		}
		class TEST_FAIL{
			int age = 21;

			public int getAge() {
				return age;
			}
		}
		Authentication auth = new UsernamePasswordAuthenticationToken("user", "password", authorities);
		assertThat(policyChecker.check(auth, "", "", "")).isFalse();
		assertThat(policyChecker.check(auth, "", "EDIT", "")).isTrue();
		assertThat(policyChecker.check(auth, new TEST(), "", "")).isTrue();
		assertThat(policyChecker.check(auth, new TEST_FAIL(), "", "")).isFalse();
	}


}
