/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.providers.dao.memory;

import net.sf.acegisecurity.providers.dao.AuthenticationDao;
import net.sf.acegisecurity.providers.dao.User;
import net.sf.acegisecurity.providers.dao.UsernameNotFoundException;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.dao.DataAccessException;


/**
 * Retrieves user details from an in-memory list created by the bean context.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class InMemoryDaoImpl implements AuthenticationDao, InitializingBean {
    //~ Instance fields ========================================================

    private UserMap userMap;

    //~ Methods ================================================================

    public void setUserMap(UserMap userMap) {
        this.userMap = userMap;
    }

    public UserMap getUserMap() {
        return userMap;
    }

    public void afterPropertiesSet() throws Exception {
        if (this.userMap == null) {
            throw new IllegalArgumentException("A list of users, passwords, enabled/disabled status and their granted authorities must be set");
        }
    }

    public User loadUserByUsername(String username)
                            throws UsernameNotFoundException, 
                                   DataAccessException {
        User result = userMap.getUser(username);

        if (result == null) {
            throw new UsernameNotFoundException("User could not be found");
        }

        return result;
    }
}
