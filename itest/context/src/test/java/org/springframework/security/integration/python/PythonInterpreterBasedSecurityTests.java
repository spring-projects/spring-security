package org.springframework.security.integration.python;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@ContextConfiguration(locations={"/python-method-access-app-context.xml"})
@RunWith(SpringJUnit4ClassRunner.class)
public class PythonInterpreterBasedSecurityTests {

    @Autowired
    private TestService service;

    @Test
    public void serviceMethod() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("bob","bobspassword"));

//        for (int i=0; i < 1000; i++) {
            service.someMethod();
//        }
    }
}
