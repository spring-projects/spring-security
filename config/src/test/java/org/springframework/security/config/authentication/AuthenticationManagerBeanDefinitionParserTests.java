package org.springframework.security.config.authentication;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.springframework.context.ApplicationListener;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.util.FieldUtils;

/**
 *
 * @author Luke Taylor
 */
public class AuthenticationManagerBeanDefinitionParserTests {
    private static final String CONTEXT =
              "<authentication-manager id='am'>" +
              "    <authentication-provider>" +
              "        <user-service>" +
              "            <user name='bob' password='bobspassword' authorities='ROLE_A,ROLE_B' />" +
              "        </user-service>" +
              "    </authentication-provider>" +
              "</authentication-manager>";
    private AbstractXmlApplicationContext appContext;

    @Test
    // SEC-1225
    public void providersAreRegisteredAsTopLevelBeans() throws Exception {
        setContext(CONTEXT);
        assertEquals(1, appContext.getBeansOfType(AuthenticationProvider.class).size());
    }

    @Test
    public void eventsArePublishedByDefault() throws Exception {
        setContext(CONTEXT);
        AuthListener listener = new AuthListener();
        appContext.addApplicationListener(listener);

        ProviderManager pm = (ProviderManager) appContext.getBeansOfType(ProviderManager.class).values().toArray()[0];
        Object eventPublisher = FieldUtils.getFieldValue(pm, "eventPublisher");
        assertNotNull(eventPublisher);
        assertTrue(eventPublisher instanceof DefaultAuthenticationEventPublisher);

        pm.authenticate(new UsernamePasswordAuthenticationToken("bob", "bobspassword"));
        assertEquals(1, listener.events.size());
    }

    @Test
    public void credentialsAreClearedByDefault() throws Exception {
        setContext(CONTEXT);
        ProviderManager pm = (ProviderManager) appContext.getBeansOfType(ProviderManager.class).values().toArray()[0];
        assertTrue(pm.isEraseCredentialsAfterAuthentication());
    }

    @Test
    public void clearCredentialsPropertyIsRespected() throws Exception {
        setContext("<authentication-manager erase-credentials='false'/>");
        ProviderManager pm = (ProviderManager) appContext.getBeansOfType(ProviderManager.class).values().toArray()[0];
        assertFalse(pm.isEraseCredentialsAfterAuthentication());
    }

    private void setContext(String context) {
        appContext = new InMemoryXmlApplicationContext(context);
    }

    private static class AuthListener implements ApplicationListener<AbstractAuthenticationEvent> {
        List<AbstractAuthenticationEvent> events = new ArrayList<AbstractAuthenticationEvent>();

        public void onApplicationEvent(AbstractAuthenticationEvent event) {
            events.add(event);
        }
    }
}
