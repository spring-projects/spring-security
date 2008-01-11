package org.springframework.security.userdetails;

import org.springframework.security.GrantedAuthority;

import java.util.List;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public interface GroupsManager {

    List findAllGroups();

    List findUsersInGroup(String groupName);

    void createGroup(String groupName, GrantedAuthority[] authorities);
//
//    void deleteGroup(String groupName);
//
//    void renameGroup(String oldName, String newName);
//
//    void addUserToGroup(String username, String group);
//
//    void removeUserFromGroup(String username, String groupName);
//
//    GrantedAuthority[] findGroupAuthorities(String groupName);
//
//    void removeGroupAuthority(String groupName, GrantedAuthority authority);
//
//    void addGroupAuthority(String groupName, GrantedAuthority authority);
}
