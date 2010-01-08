package sample.dao.impl;

import org.springframework.stereotype.Repository;

import sample.domain.User;

/**
 * UserDAOImpl
 */
@Repository
public class UserDAOImpl extends GenericDAOImpl<User, Long> implements
        sample.dao.UserDAO {

    /**
     * Required constructor
     */
    public UserDAOImpl() {
        super(User.class);
    }

    public User findByUsername(String username) {
        return (User) getEntityManager().createNamedQuery("User.findByUsername")
                .setParameter("username", username).getSingleResult();
    }


}
