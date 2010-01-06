package org.springframework.security.integration;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.integration.multiannotation.MultiAnnotationService;
import org.springframework.security.integration.multiannotation.PreAuthorizeService;
import org.springframework.security.integration.multiannotation.SecuredService;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author Luke Taylor
 */
@ContextConfiguration(locations={"/multi-sec-annotation-app-context.xml"})
@RunWith(SpringJUnit4ClassRunner.class)
public class MultiAnnotationTests {
    private final TestingAuthenticationToken joe_a = new TestingAuthenticationToken("joe","pass","ROLE_A");
    private final TestingAuthenticationToken joe_b = new TestingAuthenticationToken("joe","pass","ROLE_B");

    @Autowired
    MultiAnnotationService service;
    @Autowired
    PreAuthorizeService preService;
    @Autowired
    SecuredService secService;

    @After
    @Before
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test(expected=AccessDeniedException.class)
    public void preAuthorizeDeniedIsDenied() {
        SecurityContextHolder.getContext().setAuthentication(joe_a);
        service.preAuthorizeDenyAllMethod();
    }

    @Test(expected=AccessDeniedException.class)
    public void preAuthorizeRoleAIsDeniedIfRoleMissing() {
        SecurityContextHolder.getContext().setAuthentication(joe_b);
        service.preAuthorizeHasRoleAMethod();
    }

    @Test
    public void preAuthorizeRoleAIsAllowedIfRolePresent() {
        SecurityContextHolder.getContext().setAuthentication(joe_a);
        service.preAuthorizeHasRoleAMethod();
    }

    @Test
    public void securedAnonymousIsAllowed() {
        SecurityContextHolder.getContext().setAuthentication(joe_a);
        service.securedAnonymousMethod();
    }

    @Test(expected=AccessDeniedException.class)
    public void securedRoleAIsDeniedIfRoleMissing() {
        SecurityContextHolder.getContext().setAuthentication(joe_b);
        service.securedRoleAMethod();
    }

    @Test
    public void securedRoleAIsAllowedIfRolePresent() {
        SecurityContextHolder.getContext().setAuthentication(joe_a);
        service.securedRoleAMethod();
    }

    @Test(expected=AccessDeniedException.class)
    public void preAuthorizedOnlyServiceDeniesIfRoleMissing() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(joe_b);
        preService.preAuthorizedMethod();
    }

    @Test(expected=AccessDeniedException.class)
    public void securedOnlyRoleAServiceDeniesIfRoleMissing() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(joe_b);
        secService.securedMethod();
    }
}
