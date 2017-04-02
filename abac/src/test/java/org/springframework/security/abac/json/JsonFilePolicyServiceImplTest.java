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
package org.springframework.security.abac.json;


import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * @author Renato Soppelsa
 * @since 5.0
 */
@RunWith(JUnit4.class)
public class JsonFilePolicyServiceImplTest {

	@Test
	public void fileReadTest(){
		JsonFilePolicyServiceImpl policyService = new JsonFilePolicyServiceImpl("test_policy.abac.json");
		assertThat(policyService.getAllPolicies()).hasSize(1);
		assertThat(policyService.getAllPolicies().get(0).getName()).isEqualTo("Admin can access everything");

	}

	@Test
	public void noCostomFileReadTest(){
		JsonFilePolicyServiceImpl policyService = new JsonFilePolicyServiceImpl(null);
		assertThat(policyService.getAllPolicies()).hasSize(4);
		assertThat(policyService.getAllPolicies().get(0).getName()).isEqualTo("Default");

	}

	@Test
	public void emptyPolicyFileReadTest(){
		JsonFilePolicyServiceImpl policyService = new JsonFilePolicyServiceImpl("empty_policy.abac.json");
		assertThat(policyService.getAllPolicies()).hasSize(0);
	}

	@Test
	public void crappyPolicyFileReadTest(){
		JsonFilePolicyServiceImpl policyService = new JsonFilePolicyServiceImpl("crappy_policy.abac.json");
		assertThat(policyService.getAllPolicies()).hasSize(0);
	}

	@Test
	public void noExistingPolicyFileReadTest(){
		JsonFilePolicyServiceImpl policyService = new JsonFilePolicyServiceImpl("I_am_for_sure_not_there_policy.abac.json");
		//getting the default
		assertThat(policyService.getAllPolicies()).hasSize(4);
		assertThat(policyService.getAllPolicies().get(0).getName()).isEqualTo("Default");
	}

	@Test
	public void typePolicyFileReadTest(){
		JsonFilePolicyServiceImpl policyService = new JsonFilePolicyServiceImpl("I_am_for_sure_not_there_policy.abac.json");
		//getting the default
		assertThat(policyService.getPolicies("String")).hasSize(2);
		assertThat(policyService.getPolicies("String").get(0).getName()).isEqualTo("Default");
		assertThat(policyService.getPolicies("String").get(1).getName()).isEqualTo("Default for String");
	}
}

