/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.providers.dao.memory;

import net.sf.acegisecurity.providers.dao.User;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.HashMap;
import java.util.Map;


/**
 * Used by {@link InMemoryDaoImpl} to store a list of users and their
 * corresponding granted authorities.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class UserMap {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(UserMap.class);

    //~ Instance fields ========================================================

    private Map userMap = new HashMap();

    //~ Methods ================================================================

    public User getUser(String username) {
        return (User) this.userMap.get(username.toLowerCase());
    }

    /**
     * Adds a user to the in-memory map.
     *
     * @param user the user to be stored
     */
    public void addUser(User user) {
        logger.info("Adding user [" + user + "]");
        this.userMap.put(user.getUsername().toLowerCase(), user);
    }
}
