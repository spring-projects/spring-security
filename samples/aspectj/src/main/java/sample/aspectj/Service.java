package sample.aspectj;

import org.springframework.security.access.annotation.Secured;

/**
 * Service which is secured on method level
 *
 * @author Mike Wiesner
 * @since 1.0
 * @version $Id$
 */
public class Service {

    @Secured("ROLE_USER")
    public void secureMethod() {
        // nothing
    }

    public void publicMethod() {
        // nothing
    }

}
