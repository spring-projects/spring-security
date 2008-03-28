/**
 * 
 */
package org.springframework.security.providers.dao;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.userdetails.User;
import org.springframework.security.userdetails.UserDetails;

public class MockUserCache implements UserCache {
    private Map cache = new HashMap();

    public UserDetails getUserFromCache(String username) {
        return (User) cache.get(username);
    }

    public void putUserInCache(UserDetails user) {
        cache.put(user.getUsername(), user);
    }

    public void removeUserFromCache(String username) {
    	cache.remove(username);
    }
}