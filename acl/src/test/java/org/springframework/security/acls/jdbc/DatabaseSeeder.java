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

package org.springframework.security.acls.jdbc;

import java.io.IOException;

import javax.sql.DataSource;

import org.springframework.core.io.Resource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.Assert;
import org.springframework.util.FileCopyUtils;

/**
 * Seeds the database for {@link JdbcMutableAclServiceTests}.
 *
 * @author Ben Alex
 */
public class DatabaseSeeder {

	public DatabaseSeeder(DataSource dataSource, Resource resource) throws IOException {
		Assert.notNull(dataSource, "dataSource required");
		Assert.notNull(resource, "resource required");

		JdbcTemplate template = new JdbcTemplate(dataSource);
		String sql = new String(FileCopyUtils.copyToByteArray(resource.getInputStream()));
		template.execute(sql);
	}

}
