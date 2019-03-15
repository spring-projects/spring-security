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
package sample.dms;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.security.util.FieldUtils;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.Assert;

/**
 * Basic JDBC implementation of {@link DocumentDao}.
 *
 * @author Ben Alex
 */
public class DocumentDaoImpl extends JdbcDaoSupport implements DocumentDao {

	private static final String INSERT_INTO_DIRECTORY = "insert into directory(directory_name, parent_directory_id) values (?,?)";
	private static final String INSERT_INTO_FILE = "insert into file(file_name, content, parent_directory_id) values (?,?,?)";
	private static final String SELECT_FROM_DIRECTORY = "select id from directory where parent_directory_id = ?";
	private static final String SELECT_FROM_DIRECTORY_NULL = "select id from directory where parent_directory_id is null";
	private static final String SELECT_FROM_FILE = "select id, file_name, content, parent_directory_id from file where parent_directory_id = ?";
	private static final String SELECT_FROM_DIRECTORY_SINGLE = "select id, directory_name, parent_directory_id from directory where id = ?";
	private static final String DELETE_FROM_FILE = "delete from file where id = ?";
	private static final String UPDATE_FILE = "update file set content = ? where id = ?";
	private static final String SELECT_IDENTITY = "call identity()";

	private Long obtainPrimaryKey() {
		Assert.isTrue(TransactionSynchronizationManager.isSynchronizationActive(),
				"Transaction must be running");
		return getJdbcTemplate().queryForObject(SELECT_IDENTITY, Long.class);
	}

	public void create(AbstractElement element) {
		Assert.notNull(element, "Element required");
		Assert.isNull(element.getId(), "Element has previously been saved");
		if (element instanceof Directory) {
			Directory directory = (Directory) element;
			Long parentId = directory.getParent() == null ? null : directory.getParent()
					.getId();
			getJdbcTemplate().update(INSERT_INTO_DIRECTORY,
					new Object[] { directory.getName(), parentId });
			FieldUtils.setProtectedFieldValue("id", directory, obtainPrimaryKey());
		}
		else if (element instanceof File) {
			File file = (File) element;
			Long parentId = file.getParent() == null ? null : file.getParent().getId();
			getJdbcTemplate().update(INSERT_INTO_FILE,
					new Object[] { file.getName(), file.getContent(), parentId });
			FieldUtils.setProtectedFieldValue("id", file, obtainPrimaryKey());
		}
		else {
			throw new IllegalArgumentException("Unsupported AbstractElement");
		}
	}

	public void delete(File file) {
		Assert.notNull(file, "File required");
		Assert.notNull(file.getId(), "File ID required");
		getJdbcTemplate().update(DELETE_FROM_FILE, new Object[] { file.getId() });
	}

	/** Executes recursive SQL as needed to build a full Directory hierarchy of objects */
	private Directory getDirectoryWithImmediateParentPopulated(final Long id) {
		return getJdbcTemplate().queryForObject(SELECT_FROM_DIRECTORY_SINGLE,
				new Object[] { id }, new RowMapper<Directory>() {
					public Directory mapRow(ResultSet rs, int rowNumber)
							throws SQLException {
						Long parentDirectoryId = new Long(rs
								.getLong("parent_directory_id"));
						Directory parentDirectory = Directory.ROOT_DIRECTORY;
						if (parentDirectoryId != null
								&& !parentDirectoryId.equals(new Long(-1))) {
							// Need to go and lookup the parent, so do that first
							parentDirectory = getDirectoryWithImmediateParentPopulated(parentDirectoryId);
						}
						Directory directory = new Directory(rs
								.getString("directory_name"), parentDirectory);
						FieldUtils.setProtectedFieldValue("id", directory,
								new Long(rs.getLong("id")));
						return directory;
					}
				});
	}

	public AbstractElement[] findElements(Directory directory) {
		Assert.notNull(directory,
				"Directory required (the ID can be null to refer to root)");
		if (directory.getId() == null) {
			List<Directory> directories = getJdbcTemplate().query(
					SELECT_FROM_DIRECTORY_NULL, new RowMapper<Directory>() {
						public Directory mapRow(ResultSet rs, int rowNumber)
								throws SQLException {
							return getDirectoryWithImmediateParentPopulated(new Long(rs
									.getLong("id")));
						}
					});
			return (AbstractElement[]) directories.toArray(new AbstractElement[] {});
		}
		List<AbstractElement> directories = getJdbcTemplate().query(
				SELECT_FROM_DIRECTORY, new Object[] { directory.getId() },
				new RowMapper<AbstractElement>() {
					public Directory mapRow(ResultSet rs, int rowNumber)
							throws SQLException {
						return getDirectoryWithImmediateParentPopulated(new Long(rs
								.getLong("id")));
					}
				});
		List<File> files = getJdbcTemplate().query(SELECT_FROM_FILE,
				new Object[] { directory.getId() }, new RowMapper<File>() {
					public File mapRow(ResultSet rs, int rowNumber) throws SQLException {
						Long parentDirectoryId = new Long(rs
								.getLong("parent_directory_id"));
						Directory parentDirectory = null;
						if (parentDirectoryId != null) {
							parentDirectory = getDirectoryWithImmediateParentPopulated(parentDirectoryId);
						}
						File file = new File(rs.getString("file_name"), parentDirectory);
						FieldUtils.setProtectedFieldValue("id", file,
								new Long(rs.getLong("id")));
						return file;
					}
				});
		// Add the File elements after the Directory elements
		directories.addAll(files);
		return (AbstractElement[]) directories.toArray(new AbstractElement[] {});
	}

	public void update(File file) {
		Assert.notNull(file, "File required");
		Assert.notNull(file.getId(), "File ID required");
		getJdbcTemplate().update(UPDATE_FILE,
				new Object[] { file.getContent(), file.getId() });
	}

}
