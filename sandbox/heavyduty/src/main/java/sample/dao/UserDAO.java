
package sample.dao;

import sample.domain.User;


/**
 * The Interface PatientDAO.
 */
public interface UserDAO extends GenericDAO<User,Long> {
    
    public User findByUsername(String username);
}
