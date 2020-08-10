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

package org.springframework.security.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

/**
 * Tests {@link PortMapperImpl}.
 *
 * @author Ben Alex
 */
public class PortMapperImplTests {

	// ~ Methods
	// ========================================================================================================
	@Test
	public void testDefaultMappingsAreKnown() {
		PortMapperImpl portMapper = new PortMapperImpl();
		assertThat(portMapper.lookupHttpPort(443)).isEqualTo(Integer.valueOf(80));
		assertThat(Integer.valueOf(8080)).isEqualTo(portMapper.lookupHttpPort(8443));
		assertThat(Integer.valueOf(443)).isEqualTo(portMapper.lookupHttpsPort(80));
		assertThat(Integer.valueOf(8443)).isEqualTo(portMapper.lookupHttpsPort(8080));
	}

	@Test
	public void testDetectsEmptyMap() {
		PortMapperImpl portMapper = new PortMapperImpl();

		try {
			portMapper.setPortMappings(new HashMap<>());
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}
	}

	@Test
	public void testDetectsNullMap() {
		PortMapperImpl portMapper = new PortMapperImpl();

		try {
			portMapper.setPortMappings(null);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}
	}

	@Test
	public void testGetTranslatedPortMappings() {
		PortMapperImpl portMapper = new PortMapperImpl();
		assertThat(portMapper.getTranslatedPortMappings()).hasSize(2);
	}

	@Test
	public void testRejectsOutOfRangeMappings() {
		PortMapperImpl portMapper = new PortMapperImpl();
		Map<String, String> map = new HashMap<>();
		map.put("79", "80559");

		try {
			portMapper.setPortMappings(map);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}
	}

	@Test
	public void testReturnsNullIfHttpPortCannotBeFound() {
		PortMapperImpl portMapper = new PortMapperImpl();
		assertThat(portMapper.lookupHttpPort(Integer.valueOf("34343")) == null).isTrue();
	}

	@Test
	public void testSupportsCustomMappings() {
		PortMapperImpl portMapper = new PortMapperImpl();
		Map<String, String> map = new HashMap<>();
		map.put("79", "442");

		portMapper.setPortMappings(map);

		assertThat(portMapper.lookupHttpPort(442)).isEqualTo(Integer.valueOf(79));
		assertThat(Integer.valueOf(442)).isEqualTo(portMapper.lookupHttpsPort(79));
	}

}
