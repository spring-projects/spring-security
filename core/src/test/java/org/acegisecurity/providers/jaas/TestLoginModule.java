package net.sf.acegisecurity.providers.jaas;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.security.Principal;
import java.util.Map;

/**
 * Insert comments here...
 * <br>
 *
 * @author Ray Krueger
 * @version $Id$
 */
public class TestLoginModule implements LoginModule {

    private Subject subject;
    private String user;
    private String password;

    public boolean abort() throws LoginException {
        return true;
    }

    public boolean commit() throws LoginException {
        return true;
    }

    public boolean login() throws LoginException {

        if (!user.equals("user")) {
            throw new LoginException("Bad User");
        }

        if (!password.equals("password")) {
            throw new LoginException("Bad Password");
        }

        subject.getPrincipals().add(new Principal() {
            public String getName() {
                return "TEST_PRINCIPAL";
            }
        });

        subject.getPrincipals().add(new Principal() {
            public String getName() {
                return "NULL_PRINCIPAL";
            }
        });
        return true;
    }

    public boolean logout() throws LoginException {
        return true;
    }

    public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options) {
        this.subject = subject;
        try {

            TextInputCallback textCallback = new TextInputCallback("prompt");
            NameCallback nameCallback = new NameCallback("prompt");
            PasswordCallback passwordCallback = new PasswordCallback("prompt", false);

            callbackHandler.handle(new Callback[]{textCallback, nameCallback, passwordCallback});

            password = new String(passwordCallback.getPassword());
            user = nameCallback.getName();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
