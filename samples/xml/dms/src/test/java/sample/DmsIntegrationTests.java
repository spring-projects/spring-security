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

package sample;

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

import org.junit.After;
import org.junit.Test;
import sample.dms.AbstractElement;
import sample.dms.Directory;
import sample.dms.DocumentDao;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractTransactionalJUnit4SpringContextTests;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Basic integration test for DMS sample.
 *
 * @author Ben Alex
 *
 */
@ContextConfiguration(locations = { "classpath:applicationContext-dms-shared.xml",
		"classpath:applicationContext-dms-insecure.xml" })
public class DmsIntegrationTests extends AbstractTransactionalJUnit4SpringContextTests {

	@Autowired
	protected JdbcTemplate jdbcTemplate;

	@Autowired
	protected DocumentDao documentDao;

	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	public void setDocumentDao(DocumentDao documentDao) {
		this.documentDao = documentDao;
	}

	@Test
	public void testBasePopulation() {
		assertThat(this.jdbcTemplate.queryForObject("select count(id) from DIRECTORY",
				Integer.class)).isEqualTo(9);
		assertThat((int) this.jdbcTemplate.queryForObject("select count(id) from FILE",
				Integer.class)).isEqualTo(90);
		assertThat(this.documentDao.findElements(Directory.ROOT_DIRECTORY).length)
				.isEqualTo(3);
	}

	@Test
	public void testMarissaRetrieval() {
		process("rod", "koala", false);
	}

	@Test
	public void testScottRetrieval() {
		process("scott", "wombat", false);
	}

	@Test
	public void testDianneRetrieval() {
		process("dianne", "emu", false);
	}

	protected void process(String username, String password, boolean shouldBeFiltered) {
		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken(username, password));
		System.out.println("------ Test for username: " + username + " ------");
		AbstractElement[] rootElements = this.documentDao
				.findElements(Directory.ROOT_DIRECTORY);
		assertThat(rootElements).hasSize(3);
		Directory homeDir = null;
		Directory nonHomeDir = null;
		for (AbstractElement rootElement : rootElements) {
			if (rootElement.getName().equals(username)) {
				homeDir = (Directory) rootElement;
			}
			else {
				nonHomeDir = (Directory) rootElement;
			}
		}
		System.out.println("Home directory......: " + homeDir.getFullName());
		System.out.println("Non-home directory..: " + nonHomeDir.getFullName());

		AbstractElement[] homeElements = this.documentDao.findElements(homeDir);
		assertThat(homeElements).hasSize(12); // confidential and shared
														// directories,
		// plus 10 files

		AbstractElement[] nonHomeElements = this.documentDao.findElements(nonHomeDir);
		assertThat(nonHomeElements).hasSize(shouldBeFiltered ? 11 : 12);

		// cannot see the user's "confidential" sub-directory when filtering

		// Attempt to read the other user's confidential directory from the returned
		// results
		// Of course, we shouldn't find a "confidential" directory in the results if we're
		// filtering
		Directory nonHomeConfidentialDir = null;
		for (AbstractElement nonHomeElement : nonHomeElements) {
			if (nonHomeElement.getName().equals("confidential")) {
				nonHomeConfidentialDir = (Directory) nonHomeElement;
			}
		}

		if (shouldBeFiltered) {
			assertThat(nonHomeConfidentialDir)
					.withFailMessage(
							"Found confidential directory when we should not have")
					.isNull();
		}
		else {
			System.out.println(
					"Inaccessible dir....: " + nonHomeConfidentialDir.getFullName());
			assertThat(this.documentDao.findElements(nonHomeConfidentialDir).length)
					.isEqualTo(10); // 10
			// files
			// (no
			// sub-directories)
		}

		SecurityContextHolder.clearContext();
	}

}
