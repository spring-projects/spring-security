

package sample.domain;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Basic;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.NamedQuery;

/**
 * The Class Patient.
 */
@Entity
@NamedQuery(name = "User.findByUsername", query = "from User where username= :username")
public class User implements Serializable {

    /** serialVersionUID */
    private static final long serialVersionUID = 7073017148588882593L;

    /** The id. */
    @Id
    @GeneratedValue(strategy=GenerationType.IDENTITY)
    private Long id;

    /** The username. */
    @Basic(optional = false)
    private String username;

    /** The username. */
    @Basic(optional = false)
    private String password;

    /**
     * Default constructor
     */
    public User() {
        super();
    }

    /**
     * @param username
     * @param password
     */
    public User(String username, String password) {
        super();
        this.username = username;
        this.password = password;
    }

    /**
     * @return the id
     */
    public Long getId() {
        return id;
    }

    /**
     * @param id the id to set
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * @return the username
     */
    public String getUsername() {
        return username;
    }

    /**
     * @param username the username to set
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Full constructor
     * @param username
     */
    public User(String username, String password, Date derniereConnexion,
            String key) {
        super();
        this.username = username;
    }

    /**
     * @return the password
     */
    public String getPassword() {
        return password;
    }

    /**
     * @param password the password to set
     */
    public void setPassword(String password) {
        this.password = password;
    }
}
