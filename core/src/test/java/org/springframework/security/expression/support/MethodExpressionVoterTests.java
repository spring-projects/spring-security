package org.springframework.security.expression.support;

import static org.junit.Assert.assertEquals;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.annotation.ExpressionProtectedBusinessServiceImpl;
import org.springframework.security.expression.support.AbstractExpressionBasedMethodConfigAttribute;
import org.springframework.security.expression.support.MethodExpressionVoter;
import org.springframework.security.providers.TestingAuthenticationToken;
import org.springframework.security.util.SimpleMethodInvocation;
import org.springframework.security.vote.AccessDecisionVoter;

public class MethodExpressionVoterTests {
    private TestingAuthenticationToken joe = new TestingAuthenticationToken("joe", "joespass", "blah");
    private MethodInvocation miStringArgs;
    private MethodInvocation miListArg;
    private List listArg;

    @Before
    public void setUp() throws Exception {
        Method m = ExpressionProtectedBusinessServiceImpl.class.getMethod("methodReturningAList",
                String.class, String.class);
        miStringArgs = new SimpleMethodInvocation(new Object(), m, new String[] {"joe", "arg2Value"});
        m = ExpressionProtectedBusinessServiceImpl.class.getMethod("methodReturningAList", List.class);
        listArg = new ArrayList(Arrays.asList("joe", "bob"));
        miListArg = new SimpleMethodInvocation(new Object(), m, new Object[] {listArg});
    }

    @Test
    public void hasRoleExpressionAllowsUserWithRole() throws Exception {
        MethodExpressionVoter am = new MethodExpressionVoter();
        ConfigAttributeDefinition cad = new ConfigAttributeDefinition(new PreInvocationExpressionBasedMethodConfigAttribute(null, null, "hasRole('blah')"));

        assertEquals(AccessDecisionVoter.ACCESS_GRANTED, am.vote(joe, miStringArgs, cad));
    }

    @Test
    public void hasRoleExpressionDeniesUserWithoutRole() throws Exception {
        MethodExpressionVoter am = new MethodExpressionVoter();
        ConfigAttributeDefinition cad = new ConfigAttributeDefinition(new PreInvocationExpressionBasedMethodConfigAttribute(null, null, "hasRole('joedoesnt')"));

        assertEquals(AccessDecisionVoter.ACCESS_DENIED, am.vote(joe, miStringArgs, cad));
    }

    @Test
    public void matchingArgAgainstAuthenticationNameIsSuccessful() throws Exception {
        MethodExpressionVoter am = new MethodExpressionVoter();
        ConfigAttributeDefinition cad = new ConfigAttributeDefinition(new PreInvocationExpressionBasedMethodConfigAttribute(null, null, "(#userName == name) and (name == 'joe')"));

        assertEquals(AccessDecisionVoter.ACCESS_GRANTED, am.vote(joe, miStringArgs, cad));
    }

    @Test
    public void accessIsGrantedIfNoPreAuthorizeAttributeIsUsed() throws Exception {
        MethodExpressionVoter am = new MethodExpressionVoter();
        ConfigAttributeDefinition cad = new ConfigAttributeDefinition(new PreInvocationExpressionBasedMethodConfigAttribute("(name == 'jim')", "someList", null));

        assertEquals(AccessDecisionVoter.ACCESS_GRANTED, am.vote(joe, miListArg, cad));
        // All objects should have been removed, because the expression is always false
        assertEquals(0, listArg.size());
    }

}
