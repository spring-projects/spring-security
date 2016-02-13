package org.springframework.security.util;

import static org.assertj.core.api.Assertions.*;

import org.junit.*;

/**
 * @author Luke Taylor
 */
public class InMemoryResourceTests {

	@Test
	public void resourceContainsExpectedData() throws Exception {
		InMemoryResource resource = new InMemoryResource("blah");
		assertThat(resource.getDescription()).isNull();
		assertThat(resource.hashCode()).isEqualTo(1);
		assertThat(resource.getInputStream()).isNotNull();
	}

	@Test
	public void resourceIsEqualToOneWithSameContent() throws Exception {
		assertThat(new InMemoryResource("xxx")).isEqualTo(new InMemoryResource("xxx"));
		assertThat(new InMemoryResource("xxx").equals(new InMemoryResource("xxxx"))).isFalse();
		assertThat(new InMemoryResource("xxx").equals(new Object())).isFalse();
	}
}
