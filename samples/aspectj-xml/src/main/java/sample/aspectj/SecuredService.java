package sample.aspectj;

import org.springframework.security.access.annotation.Secured;

/**
 * Service which is secured on the class level
 *
 * @author Mike Wiesner
 * @since 3.0
 */
@Secured("ROLE_USER")
public class SecuredService {

    public void secureMethod() {
        // nothing
    }

}
