package org.springframework.security.access.intercept.aspectj.aspect;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.annotation.SecuredAnnotationSecurityMetadataSource;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.ExpressionBasedAnnotationAttributeFactory;
import org.springframework.security.access.expression.method.ExpressionBasedPostInvocationAdvice;
import org.springframework.security.access.expression.method.ExpressionBasedPreInvocationAdvice;
import org.springframework.security.access.intercept.AfterInvocationProviderManager;
import org.springframework.security.access.intercept.aspectj.AspectJMethodSecurityInterceptor;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PostInvocationAdviceProvider;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdviceVoter;
import org.springframework.security.access.prepost.PrePostAnnotationSecurityMetadataSource;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 *
 * @author Luke Taylor
 * @since 3.0.3
 */
public class AnnotationSecurityAspectTests {
    private AffirmativeBased adm;
    private @Mock AuthenticationManager authman;
    private TestingAuthenticationToken anne = new TestingAuthenticationToken("anne", "", "ROLE_A");
//    private TestingAuthenticationToken bob = new TestingAuthenticationToken("bob", "", "ROLE_B");
    private AspectJMethodSecurityInterceptor interceptor;
    private SecuredImpl secured = new SecuredImpl();
    private SecuredImplSubclass securedSub = new SecuredImplSubclass();
    private PrePostSecured prePostSecured = new PrePostSecured();

    @Before
    public final void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        interceptor = new AspectJMethodSecurityInterceptor();
        adm = new AffirmativeBased();
        AccessDecisionVoter[] voters = new AccessDecisionVoter[]
                {new RoleVoter(), new PreInvocationAuthorizationAdviceVoter(new ExpressionBasedPreInvocationAdvice())};
        adm.setDecisionVoters(Arrays.asList(voters));
        interceptor.setAccessDecisionManager(adm);
        interceptor.setAuthenticationManager(authman);
        interceptor.setSecurityMetadataSource(new SecuredAnnotationSecurityMetadataSource());
        AnnotationSecurityAspect secAspect = AnnotationSecurityAspect.aspectOf();
        secAspect.setSecurityInterceptor(interceptor);
    }

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void securedInterfaceMethodAllowsAllAccess() throws Exception {
        secured.securedMethod();
    }

    @Test(expected=AuthenticationCredentialsNotFoundException.class)
    public void securedClassMethodDeniesUnauthenticatedAccess() throws Exception {
        secured.securedClassMethod();
    }

    @Test
    public void securedClassMethodAllowsAccessToRoleA() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(anne);
        secured.securedClassMethod();
    }

    @Test(expected=AccessDeniedException.class)
    public void internalPrivateCallIsIntercepted() {
        SecurityContextHolder.getContext().setAuthentication(anne);

        try {
            secured.publicCallsPrivate();
            fail("Expected AccessDeniedException");
        } catch (AccessDeniedException expected) {
        }
        securedSub.publicCallsPrivate();
    }

    @Test(expected=AccessDeniedException.class)
    public void protectedMethodIsIntercepted() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(anne);

        secured.protectedMethod();
    }

    @Test
    public void overriddenProtectedMethodIsNotIntercepted() throws Exception {
        // AspectJ doesn't inherit annotations
        securedSub.protectedMethod();
    }

    // SEC-1262
    @Test(expected=AccessDeniedException.class)
    public void denyAllPreAuthorizeDeniesAccess() throws Exception {
        configureForElAnnotations();
        SecurityContextHolder.getContext().setAuthentication(anne);
        prePostSecured.denyAllMethod();
    }

    @Test
    public void postFilterIsApplied() throws Exception {
        configureForElAnnotations();
        SecurityContextHolder.getContext().setAuthentication(anne);
        List<String> objects = prePostSecured.postFilterMethod();
        assertEquals(2, objects.size());
        assertTrue(objects.contains("apple"));
        assertTrue(objects.contains("aubergine"));
    }

    private void configureForElAnnotations() {
        DefaultMethodSecurityExpressionHandler eh = new DefaultMethodSecurityExpressionHandler();
        interceptor.setSecurityMetadataSource(new PrePostAnnotationSecurityMetadataSource(
                new ExpressionBasedAnnotationAttributeFactory(eh)));
        interceptor.setAccessDecisionManager(adm);
        AfterInvocationProviderManager aim = new AfterInvocationProviderManager();
        aim.setProviders(Arrays.asList(new PostInvocationAdviceProvider(new ExpressionBasedPostInvocationAdvice(eh))));
        interceptor.setAfterInvocationManager(aim);
    }
}

interface SecuredInterface {
    @Secured("ROLE_X")
    void securedMethod();
}

class SecuredImpl implements SecuredInterface {
    // Not really secured because AspectJ doesn't inherit annotations from interfaces
    public void securedMethod() {
    }

    @Secured("ROLE_A")
    public void securedClassMethod() {
    }

    @Secured("ROLE_X")
    private void privateMethod() {
    }

    @Secured("ROLE_X")
    protected void protectedMethod() {
    }

    @Secured("ROLE_X")
    public void publicCallsPrivate() {
        privateMethod();
    }
}

class SecuredImplSubclass extends SecuredImpl {
    protected void protectedMethod() {
    }

    public void publicCallsPrivate() {
        super.publicCallsPrivate();
    }
}

class PrePostSecured {
    @PreAuthorize("denyAll")
    public void denyAllMethod() {
    }

    @PostFilter("filterObject.startsWith('a')")
    public List<String> postFilterMethod() {
        ArrayList<String> objects = new ArrayList<String>();
        objects.addAll(Arrays.asList(new String[] {"apple", "banana", "aubergine", "orange"}));
        return objects;
    }
}
