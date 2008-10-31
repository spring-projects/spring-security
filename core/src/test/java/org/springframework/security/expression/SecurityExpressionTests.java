package org.springframework.security.expression;

import org.junit.Test;
import org.springframework.expression.spel.standard.StandardEvaluationContext;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;


/**
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class SecurityExpressionTests {
    @Test
    public void someTestMethod() throws Exception {
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken("joe", "password");

        SecurityExpressionRoot root = new SecurityExpressionRoot(authToken);
        StandardEvaluationContext ctx = new StandardEvaluationContext();
        
        


    }

    @Test
    public void someTestMethod2() throws Exception {

    }
}
