package samples.gae.users;

import com.google.appengine.api.datastore.EntityNotFoundException;

/**
 *
 * Service used to maintain a list of users who are registered with the application.
 *
 * @author Luke Taylor
 */
public interface UserRegistry {

    GaeUser findUser(String userId);

    void registerUser(GaeUser newUser);

    void removeUser(String userId);
}
