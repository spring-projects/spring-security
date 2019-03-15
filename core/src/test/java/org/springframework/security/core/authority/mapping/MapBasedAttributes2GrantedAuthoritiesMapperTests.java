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
package org.springframework.security.core.authority.mapping;

import static org.assertj.core.api.Assertions.*;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.*;

/**
 *
 * @author Ruud Senden
 */
@SuppressWarnings("unchecked")
public class MapBasedAttributes2GrantedAuthoritiesMapperTests {

	@Test(expected = IllegalArgumentException.class)
	public void testAfterPropertiesSetNoMap() throws Exception {
		MapBasedAttributes2GrantedAuthoritiesMapper mapper = new MapBasedAttributes2GrantedAuthoritiesMapper();
		mapper.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAfterPropertiesSetEmptyMap() throws Exception {
		MapBasedAttributes2GrantedAuthoritiesMapper mapper = new MapBasedAttributes2GrantedAuthoritiesMapper();
		mapper.setAttributes2grantedAuthoritiesMap(new HashMap());
		mapper.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAfterPropertiesSetInvalidKeyTypeMap() throws Exception {
		MapBasedAttributes2GrantedAuthoritiesMapper mapper = new MapBasedAttributes2GrantedAuthoritiesMapper();
		HashMap m = new HashMap();
		m.put(new Object(), "ga1");
		mapper.setAttributes2grantedAuthoritiesMap(m);
		mapper.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAfterPropertiesSetInvalidValueTypeMap1() throws Exception {
		MapBasedAttributes2GrantedAuthoritiesMapper mapper = new MapBasedAttributes2GrantedAuthoritiesMapper();
		HashMap m = new HashMap();
		m.put("role1", new Object());
		mapper.setAttributes2grantedAuthoritiesMap(m);
		mapper.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAfterPropertiesSetInvalidValueTypeMap2() throws Exception {
		MapBasedAttributes2GrantedAuthoritiesMapper mapper = new MapBasedAttributes2GrantedAuthoritiesMapper();
		HashMap m = new HashMap();
		m.put("role1", new Object[] { new String[] { "ga1", "ga2" }, new Object() });
		mapper.setAttributes2grantedAuthoritiesMap(m);
		mapper.afterPropertiesSet();
	}

	@Test
	public void testAfterPropertiesSetValidMap() throws Exception {
		MapBasedAttributes2GrantedAuthoritiesMapper mapper = new MapBasedAttributes2GrantedAuthoritiesMapper();
		HashMap m = getValidAttributes2GrantedAuthoritiesMap();
		mapper.setAttributes2grantedAuthoritiesMap(m);
		mapper.afterPropertiesSet();
	}

	@Test
	public void testMapping1() throws Exception {
		String[] roles = { "role1" };
		String[] expectedGas = { "ga1" };
		testGetGrantedAuthorities(getDefaultMapper(), roles, expectedGas);
	}

	@Test
	public void testMapping2() throws Exception {
		String[] roles = { "role2" };
		String[] expectedGas = { "ga2" };
		testGetGrantedAuthorities(getDefaultMapper(), roles, expectedGas);
	}

	@Test
	public void testMapping3() throws Exception {
		String[] roles = { "role3" };
		String[] expectedGas = { "ga3", "ga4" };
		testGetGrantedAuthorities(getDefaultMapper(), roles, expectedGas);
	}

	@Test
	public void testMapping4() throws Exception {
		String[] roles = { "role4" };
		String[] expectedGas = { "ga5", "ga6" };
		testGetGrantedAuthorities(getDefaultMapper(), roles, expectedGas);
	}

	@Test
	public void testMapping5() throws Exception {
		String[] roles = { "role5" };
		String[] expectedGas = { "ga7", "ga8", "ga9" };
		testGetGrantedAuthorities(getDefaultMapper(), roles, expectedGas);
	}

	@Test
	public void testMapping6() throws Exception {
		String[] roles = { "role6" };
		String[] expectedGas = { "ga10", "ga11", "ga12" };
		testGetGrantedAuthorities(getDefaultMapper(), roles, expectedGas);
	}

	@Test
	public void testMapping7() throws Exception {
		String[] roles = { "role7" };
		String[] expectedGas = { "ga13", "ga14" };
		testGetGrantedAuthorities(getDefaultMapper(), roles, expectedGas);
	}

	@Test
	public void testMapping8() throws Exception {
		String[] roles = { "role8" };
		String[] expectedGas = { "ga13", "ga14" };
		testGetGrantedAuthorities(getDefaultMapper(), roles, expectedGas);
	}

	@Test
	public void testMapping9() throws Exception {
		String[] roles = { "role9" };
		String[] expectedGas = {};
		testGetGrantedAuthorities(getDefaultMapper(), roles, expectedGas);
	}

	@Test
	public void testMapping10() throws Exception {
		String[] roles = { "role10" };
		String[] expectedGas = {};
		testGetGrantedAuthorities(getDefaultMapper(), roles, expectedGas);
	}

	@Test
	public void testMapping11() throws Exception {
		String[] roles = { "role11" };
		String[] expectedGas = {};
		testGetGrantedAuthorities(getDefaultMapper(), roles, expectedGas);
	}

	@Test
	public void testNonExistingMapping() throws Exception {
		String[] roles = { "nonExisting" };
		String[] expectedGas = {};
		testGetGrantedAuthorities(getDefaultMapper(), roles, expectedGas);
	}

	@Test
	public void testMappingCombination() throws Exception {
		String[] roles = { "role1", "role2", "role3", "role4", "role5", "role6", "role7",
				"role8", "role9", "role10", "role11" };
		String[] expectedGas = { "ga1", "ga2", "ga3", "ga4", "ga5", "ga6", "ga7", "ga8",
				"ga9", "ga10", "ga11", "ga12", "ga13", "ga14" };
		testGetGrantedAuthorities(getDefaultMapper(), roles, expectedGas);
	}

	private HashMap getValidAttributes2GrantedAuthoritiesMap() {
		HashMap m = new HashMap();
		m.put("role1", "ga1");
		m.put("role2", new SimpleGrantedAuthority("ga2"));
		m.put("role3", Arrays.asList("ga3", new SimpleGrantedAuthority("ga4")));
		m.put("role4", "ga5,ga6");
		m.put("role5", Arrays.asList("ga7", "ga8",
				new Object[] { new SimpleGrantedAuthority("ga9") }));
		m.put("role6", new Object[] { "ga10", "ga11",
				new Object[] { new SimpleGrantedAuthority("ga12") } });
		m.put("role7", new String[] { "ga13", "ga14" });
		m.put("role8", new String[] { "ga13", "ga14", null });
		m.put("role9", null);
		m.put("role10", new Object[] {});
		m.put("role11", Arrays.asList(new Object[] { null }));
		return m;
	}

	private MapBasedAttributes2GrantedAuthoritiesMapper getDefaultMapper()
			throws Exception {
		MapBasedAttributes2GrantedAuthoritiesMapper mapper = new MapBasedAttributes2GrantedAuthoritiesMapper();
		mapper.setAttributes2grantedAuthoritiesMap(getValidAttributes2GrantedAuthoritiesMap());
		mapper.afterPropertiesSet();
		return mapper;
	}

	private void testGetGrantedAuthorities(
			MapBasedAttributes2GrantedAuthoritiesMapper mapper, String[] roles,
			String[] expectedGas) {
		List<GrantedAuthority> result = mapper
				.getGrantedAuthorities(Arrays.asList(roles));
		Collection resultColl = new ArrayList(result.size());
		for (GrantedAuthority auth : result) {
			resultColl.add(auth.getAuthority());
		}
		Collection expectedColl = Arrays.asList(expectedGas);
		assertThat(resultColl.containsAll(expectedColl)).withFailMessage("Role collections should match; result: " + resultColl
				+ ", expected: " + expectedColl).isTrue();
	}
}
