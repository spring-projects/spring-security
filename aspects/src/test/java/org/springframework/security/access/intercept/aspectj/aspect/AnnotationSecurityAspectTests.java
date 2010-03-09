package org.springframework.security.access.intercept.aspectj.aspect;

import java.util.Arrays;

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
import org.springframework.security.access.expression.method.ExpressionBasedPreInvocationAdvice;
import org.springframework.security.access.intercept.aspectj.AspectJMethodSecurityInterceptor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdviceVoter;
import org.springframework.security.access.prepost.PrePostAnnotationSecurityMetadataSource;
import org.springframework.security.access.vote.AffirmativeBased;
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
    private @Mock AccessDecisionManager adm;
    private @Mock AuthenticationManager authman;
    private TestingAuthenticationToken anne = new TestingAuthenticationToken("anne", "", "ROLE_A");
//    private TestingAuthenticationToken bob = new TestingAuthenticationToken("bob", "", "ROLE_B");
    private AspectJMethodSecurityInterceptor interceptor;
    private SecuredImpl secured = new SecuredImpl();
    private PrePostSecured prePostSecured = new PrePostSecured();

    @Before
    public final void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        interceptor = new AspectJMethodSecurityInterceptor();
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

    // SEC-1262
    @Test(expected=AccessDeniedException.class)
    public void denyAllPreAuthorizeDeniesAccess() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(anne);
        interceptor.setSecurityMetadataSource(new PrePostAnnotationSecurityMetadataSource(
                new ExpressionBasedAnnotationAttributeFactory(new DefaultMethodSecurityExpressionHandler())));
        AffirmativeBased adm = new AffirmativeBased();
        AccessDecisionVoter[] voters = new AccessDecisionVoter[]
                       {new PreInvocationAuthorizationAdviceVoter(new ExpressionBasedPreInvocationAdvice())};
        adm.setDecisionVoters(Arrays.asList(voters));
        interceptor.setAccessDecisionManager(adm);
        prePostSecured.denyAllMethod();
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
}

class PrePostSecured {

    @PreAuthorize("denyAll")
    public void denyAllMethod() {
    }
}
