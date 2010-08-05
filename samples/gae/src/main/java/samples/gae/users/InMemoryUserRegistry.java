package samples.gae.users;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;

/**
 * @author Luke Taylor
 */
public class InMemoryUserRegistry implements UserRegistry {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final Map<String, GaeUser> users = Collections.synchronizedMap(new HashMap<String, GaeUser>());

    public GaeUser findUser(String userId) {
        return users.get(userId);
    }

    public void registerUser(GaeUser newUser) {
        logger.debug("Attempting to create new user " + newUser);

        Assert.state(!users.containsKey(newUser.getUserId()));

        users.put(newUser.getUserId(), newUser);
    }

    public void removeUser(String userId) {
        users.remove(userId);
    }
}
