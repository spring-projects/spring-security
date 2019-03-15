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
package org.springframework.security.provisioning;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;

/**
 * Allows management of groups of authorities and their members.
 * <p>
 * Typically this will be used to supplement the functionality of a
 * {@link UserDetailsManager} in situations where the organization of application granted
 * authorities into groups is preferred over a straight mapping of users to roles.
 * <p>
 * With this scenario, users are allocated to groups and take on the list of authorities
 * which are assigned to the group, providing more flexible administration options.
 *
 * @author Luke Taylor
 */
public interface GroupManager {

	/**
	 * Returns the names of all groups that this group manager controls.
	 */
	List<String> findAllGroups();

	/**
	 * Locates the users who are members of a group
	 *
	 * @param groupName the group whose members are required
	 * @return the usernames of the group members
	 */
	List<String> findUsersInGroup(String groupName);

	/**
	 * Creates a new group with the specified list of authorities.
	 *
	 * @param groupName the name for the new group
	 * @param authorities the authorities which are to be allocated to this group.
	 */
	void createGroup(String groupName, List<GrantedAuthority> authorities);

	/**
	 * Removes a group, including all members and authorities.
	 *
	 * @param groupName the group to remove.
	 */
	void deleteGroup(String groupName);

	/**
	 * Changes the name of a group without altering the assigned authorities or members.
	 */
	void renameGroup(String oldName, String newName);

	/**
	 * Makes a user a member of a particular group.
	 *
	 * @param username the user to be given membership.
	 * @param group the name of the group to which the user will be added.
	 */
	void addUserToGroup(String username, String group);

	/**
	 * Deletes a user's membership of a group.
	 *
	 * @param username the user
	 * @param groupName the group to remove them from
	 */
	void removeUserFromGroup(String username, String groupName);

	/**
	 * Obtains the list of authorities which are assigned to a group.
	 */
	List<GrantedAuthority> findGroupAuthorities(String groupName);

	/**
	 * Assigns a new authority to a group.
	 */
	void addGroupAuthority(String groupName, GrantedAuthority authority);

	/**
	 * Deletes an authority from those assigned to a group
	 */
	void removeGroupAuthority(String groupName, GrantedAuthority authority);
}
