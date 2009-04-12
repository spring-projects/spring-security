package org.springframework.security.integration;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.concurrent.SessionRegistry;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
@ContextConfiguration(locations={"/sec-936-app-context.xml"})
@RunWith(SpringJUnit4ClassRunner.class)
public class SEC936ApplicationContextTests {
    @Autowired
    /** SessionRegistry is used as the test service interface (nothing to do with the test) */
    private SessionRegistry sessionRegistry;

    @Test(expected=AccessDeniedException.class)
    public void securityInterceptorHandlesCallWithNoTargetObject() {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("bob","bobspassword"));
        sessionRegistry.getAllPrincipals();
    }

}
