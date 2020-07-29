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

package sample;

import org.junit.Test;

import org.springframework.test.context.ContextConfiguration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Basic integration test for DMS sample when security has been added.
 *
 * @author Ben Alex
 *
 */
@ContextConfiguration(locations = { "classpath:applicationContext-dms-shared.xml",
		"classpath:applicationContext-dms-secure.xml" })
public class SecureDmsIntegrationTests extends DmsIntegrationTests {

	@Override
	@Test
	public void testBasePopulation() {
		assertThat(this.jdbcTemplate.queryForObject("select count(id) from DIRECTORY",
				Integer.class)).isEqualTo(9);
		assertThat(this.jdbcTemplate.queryForObject("select count(id) from FILE",
				Integer.class)).isEqualTo(90);
		assertThat(this.jdbcTemplate.queryForObject("select count(id) from ACL_SID",
				Integer.class)).isEqualTo(4); // 3 users + 1 role
		assertThat(this.jdbcTemplate.queryForObject("select count(id) from ACL_CLASS",
				Integer.class)).isEqualTo(2); // Directory
		// and
		// File
		assertThat(this.jdbcTemplate.queryForObject(
				"select count(id) from ACL_OBJECT_IDENTITY", Integer.class))
						.isEqualTo(100);
		assertThat(this.jdbcTemplate.queryForObject("select count(id) from ACL_ENTRY",
				Integer.class)).isEqualTo(115);
	}

	@Override
	public void testMarissaRetrieval() {
		process("rod", "koala", true);
	}

	@Override
	public void testScottRetrieval() {
		process("scott", "wombat", true);
	}

	@Override
	public void testDianneRetrieval() {
		process("dianne", "emu", true);
	}
}
