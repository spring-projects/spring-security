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

package sample.contact;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.support.JdbcDaoSupport;

/**
 * Base implementation of {@link ContactDao} that uses Spring's JdbcTemplate.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class ContactDaoSpring extends JdbcDaoSupport implements ContactDao {

	// ~ Methods
	// ========================================================================================================

	public void create(final Contact contact) {
		getJdbcTemplate().update("insert into contacts values (?, ?, ?)",
				new PreparedStatementSetter() {
					public void setValues(PreparedStatement ps) throws SQLException {
						ps.setLong(1, contact.getId());
						ps.setString(2, contact.getName());
						ps.setString(3, contact.getEmail());
					}
				});
	}

	public void delete(final Long contactId) {
		getJdbcTemplate().update("delete from contacts where id = ?",
				new PreparedStatementSetter() {
					public void setValues(PreparedStatement ps) throws SQLException {
						ps.setLong(1, contactId);
					}
				});
	}

	public void update(final Contact contact) {
		getJdbcTemplate().update(
				"update contacts set contact_name = ?, address = ? where id = ?",
				new PreparedStatementSetter() {
					public void setValues(PreparedStatement ps) throws SQLException {
						ps.setString(1, contact.getName());
						ps.setString(2, contact.getEmail());
						ps.setLong(3, contact.getId());
					}
				});
	}

	public List<Contact> findAll() {
		return getJdbcTemplate().query(
				"select id, contact_name, email from contacts order by id",
				new RowMapper<Contact>() {
					public Contact mapRow(ResultSet rs, int rowNum) throws SQLException {
						return mapContact(rs);
					}
				});
	}

	public List<String> findAllPrincipals() {
		return getJdbcTemplate().queryForList(
				"select username from users order by username", String.class);
	}

	public List<String> findAllRoles() {
		return getJdbcTemplate().queryForList(
				"select distinct authority from authorities order by authority",
				String.class);
	}

	public Contact getById(Long id) {
		List<Contact> list = getJdbcTemplate().query(
				"select id, contact_name, email from contacts where id = ? order by id",
				new RowMapper<Contact>() {
					public Contact mapRow(ResultSet rs, int rowNum) throws SQLException {
						return mapContact(rs);
					}
				}, id);

		if (list.size() == 0) {
			return null;
		}
		else {
			return list.get(0);
		}
	}

	private Contact mapContact(ResultSet rs) throws SQLException {
		Contact contact = new Contact();
		contact.setId(rs.getLong("id"));
		contact.setName(rs.getString("contact_name"));
		contact.setEmail(rs.getString("email"));

		return contact;
	}
}
