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
 * @version $Id$
 */
public class AuthenticationManagerBeanDefinitionParserTests {
    private static final String CONTEXT =
              "<authentication-manager>" +
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
        setContext(CONTEXT, "3.0");
        assertEquals(1, appContext.getBeansOfType(AuthenticationProvider.class).size());
    }

    @Test
    public void eventsArePublishedByDefault() throws Exception {
        setContext(CONTEXT, "3.0");
        AuthListener listener = new AuthListener();
        appContext.addApplicationListener(listener);

        ProviderManager pm = (ProviderManager) appContext.getBeansOfType(ProviderManager.class).values().toArray()[0];
        Object eventPublisher = FieldUtils.getFieldValue(pm, "eventPublisher");
        assertNotNull(eventPublisher);
        assertTrue(eventPublisher instanceof DefaultAuthenticationEventPublisher);

        pm.authenticate(new UsernamePasswordAuthenticationToken("bob", "bobspassword"));
        assertEquals(1, listener.events.size());
    }

    private void setContext(String context, String version) {
        appContext = new InMemoryXmlApplicationContext(context, version, null);
    }

    private static class AuthListener implements ApplicationListener<AbstractAuthenticationEvent> {
        List<AbstractAuthenticationEvent> events = new ArrayList<AbstractAuthenticationEvent>();

        public void onApplicationEvent(AbstractAuthenticationEvent event) {
            events.add(event);
        }
    }
}
