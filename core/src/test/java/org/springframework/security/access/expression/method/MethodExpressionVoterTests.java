package org.springframework.security.access.expression.method;

import static org.junit.Assert.assertEquals;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Test;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.expression.method.MethodExpressionVoter;
import org.springframework.security.access.expression.method.PreInvocationExpressionAttribute;
import org.springframework.security.access.vote.AccessDecisionVoter;
import org.springframework.security.providers.TestingAuthenticationToken;
import org.springframework.security.util.SimpleMethodInvocation;

@SuppressWarnings("unchecked")
public class MethodExpressionVoterTests {
    private TestingAuthenticationToken joe = new TestingAuthenticationToken("joe", "joespass", "blah");
    private MethodExpressionVoter am = new MethodExpressionVoter();

    @Test
    public void hasRoleExpressionAllowsUserWithRole() throws Exception {
        MethodInvocation mi = new SimpleMethodInvocation(new TargetImpl(), methodTakingAnArray());
        assertEquals(AccessDecisionVoter.ACCESS_GRANTED, am.vote(joe, mi, createAttributes(new PreInvocationExpressionAttribute(null, null, "hasRole('blah')"))));
    }

    @Test
    public void hasRoleExpressionDeniesUserWithoutRole() throws Exception {
        List<ConfigAttribute> cad = new ArrayList<ConfigAttribute>(1);
        cad.add(new PreInvocationExpressionAttribute(null, null, "hasRole('joedoesnt')"));
        MethodInvocation mi = new SimpleMethodInvocation(new TargetImpl(), methodTakingAnArray());
        assertEquals(AccessDecisionVoter.ACCESS_DENIED, am.vote(joe, mi, cad));
    }

    @Test
    public void matchingArgAgainstAuthenticationNameIsSuccessful() throws Exception {
        MethodInvocation mi = new SimpleMethodInvocation(new TargetImpl(), methodTakingAString(), "joe");
        assertEquals(AccessDecisionVoter.ACCESS_GRANTED,
                am.vote(joe, mi, createAttributes(new PreInvocationExpressionAttribute(null, null, "(#argument == principal) and (principal == 'joe')"))));
    }

    @Test
    public void accessIsGrantedIfNoPreAuthorizeAttributeIsUsed() throws Exception {
        Collection arg = createCollectionArg("joe", "bob", "sam");
        MethodInvocation mi = new SimpleMethodInvocation(new TargetImpl(), methodTakingACollection(), arg);
        assertEquals(AccessDecisionVoter.ACCESS_GRANTED,
                am.vote(joe, mi, createAttributes(new PreInvocationExpressionAttribute("(filterObject == 'jim')", "collection", null))));
        // All objects should have been removed, because the expression is always false
        assertEquals(0, arg.size());
    }

    @Test
    public void collectionPreFilteringIsSuccessful() throws Exception {
        List arg = createCollectionArg("joe", "bob", "sam");
        MethodInvocation mi = new SimpleMethodInvocation(new TargetImpl(), methodTakingACollection(), arg);
        am.vote(joe, mi, createAttributes(new PreInvocationExpressionAttribute("(filterObject == 'joe' or filterObject == 'sam')", "collection", "permitAll")));
        assertEquals("joe and sam should still be in the list", 2, arg.size());
        assertEquals("joe", arg.get(0));
        assertEquals("sam", arg.get(1));
    }

    @Test(expected=IllegalArgumentException.class)
    public void arraysCannotBePrefiltered() throws Exception {
        MethodInvocation mi = new SimpleMethodInvocation(new TargetImpl(), methodTakingAnArray(), createArrayArg("sam","joe"));
        am.vote(joe, mi, createAttributes(new PreInvocationExpressionAttribute("(filterObject == 'jim')", "someArray", null)));
    }

    @Test(expected=IllegalArgumentException.class)
    public void incorrectFilterTargetNameIsRejected() throws Exception {
        MethodInvocation mi = new SimpleMethodInvocation(new TargetImpl(), methodTakingACollection(), createCollectionArg("joe", "bob"));
        am.vote(joe, mi, createAttributes(new PreInvocationExpressionAttribute("(filterObject == 'joe')", "collcetion", null)));
    }

    @Test(expected=IllegalArgumentException.class)
    public void nullNamedFilterTargetIsRejected() throws Exception {
        MethodInvocation mi = new SimpleMethodInvocation(new TargetImpl(), methodTakingACollection(), new Object[] {null});
        am.vote(joe, mi, createAttributes(new PreInvocationExpressionAttribute("(filterObject == 'joe')", "collection", null)));
    }

    @Test
    public void ruleDefinedInAClassMethodIsApplied() throws Exception {
        MethodInvocation mi = new SimpleMethodInvocation(new TargetImpl(), methodTakingAString(), "joe");
        assertEquals(AccessDecisionVoter.ACCESS_GRANTED, am.vote(joe, mi,
                createAttributes(new PreInvocationExpressionAttribute(null, null, "new org.springframework.security.access.expression.method.SecurityRules().isJoe(#argument)"))));
    }

    private List<ConfigAttribute> createAttributes(ConfigAttribute... attributes) {
        return Arrays.asList(attributes);
    }

    private List createCollectionArg(Object... elts) {
        ArrayList result = new ArrayList(elts.length);
        result.addAll(Arrays.asList(elts));
        return result;
    }

    private Object createArrayArg(Object... elts) {
        ArrayList result = new ArrayList(elts.length);
        result.addAll(Arrays.asList(elts));
        return result.toArray(new Object[0]);
    }

    private Method methodTakingAnArray() throws Exception {
        return Target.class.getMethod("methodTakingAnArray", Object[].class);
    }

    private Method methodTakingAString() throws Exception {
        return Target.class.getMethod("methodTakingAString", String.class);
    }

    private Method methodTakingACollection() throws Exception {
        return Target.class.getMethod("methodTakingACollection", Collection.class);
    }


    //~ Inner Classes ==================================================================================================

    private interface Target {
        void methodTakingAnArray(Object[] args);

        void methodTakingAString(String argument);

        Collection methodTakingACollection(Collection collection);
    }

    private static class TargetImpl implements Target {
        public void methodTakingAnArray(Object[] args) {}

        public void methodTakingAString(String argument) {};

        public Collection methodTakingACollection(Collection collection) {return collection;}
    }
}
