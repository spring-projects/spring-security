/*
 * Copyright 2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.authentication.jaas;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.springframework.security.authentication.jaas.memory.InMemoryConfiguration;
import org.springframework.util.Assert;

/**
 * <p>
 * Creates a LoginContext using the Configuration provided to it. This allows
 * the configuration to be injected regardless of the value of
 * {@link Configuration#getConfiguration()}.
 * </p>
 * <p>
 * While not bound to any particular Configuration implementation, an in memory version of a JAAS
 * configuration can be represented using {@link InMemoryConfiguration}.
 * </p>
 * <p>
 * The following JAAS configuration:
 * </p>
 * 
 * <pre>
 * SPRINGSECURITY {
 *    sample.SampleLoginModule required;
 *  };
 * </pre>
 * 
 * <p>
 * Can be represented as follows:
 * </p>
 * 
 * <pre>
 * &lt;bean id=&quot;jaasAuthProvider&quot; class=&quot;org.springframework.security.authentication.jaas.DefaultJaasAuthenticationProvider&quot;&gt;
 *   &lt;property name=&quot;configuration&quot;&gt;
 *     &lt;bean class=&quot;org.springframework.security.authentication.jaas.memory.InMemoryConfiguration&quot;&gt;
 *       &lt;constructor-arg&gt;
 *         &lt;map&gt;
 *           &lt;!-- SPRINGSECURITY is the default loginContextName for AbstractJaasAuthenticationProvider--&gt;
 *           &lt;entry key=&quot;SPRINGSECURITY&quot;&gt;
 *             &lt;array&gt;
 *               &lt;bean class=&quot;javax.security.auth.login.AppConfigurationEntry&quot;&gt;
 *                 &lt;constructor-arg value=&quot;sample.SampleLoginModule&quot; /&gt;
 *                 &lt;constructor-arg&gt;
 *                   &lt;util:constant static-field=&quot;javax.security.auth.login.AppConfigurationEntry$LoginModuleControlFlag.REQUIRED&quot; /&gt;
 *                 &lt;/constructor-arg&gt;
 *                 &lt;constructor-arg&gt;
 *                   &lt;map&gt;&lt;/map&gt;
 *                 &lt;/constructor-arg&gt;
 *               &lt;/bean&gt;
 *             &lt;/array&gt;
 *           &lt;/entry&gt;
 *         &lt;/map&gt;
 *       &lt;/constructor-arg&gt;
 *     &lt;/bean&gt;
 *   &lt;/property&gt;
 *   &lt;property name=&quot;authorityGranters&quot;&gt;
 *     &lt;list&gt;
 *       &lt;!-- You will need to write your own implementation of AuthorityGranter --&gt;
 *       &lt;bean class=&quot;org.springframework.security.authentication.jaas.TestAuthorityGranter&quot;/&gt;
 *     &lt;/list&gt;
 *   &lt;/property&gt;
 * &lt;/bean&gt;
 * </pre>
 * 
 * @author Rob Winch
 * @see AbstractJaasAuthenticationProvider
 * @see InMemoryConfiguration
 */
public class DefaultJaasAuthenticationProvider extends AbstractJaasAuthenticationProvider {
    //~ Instance fields ================================================================================================

    private Configuration configuration;

    //~ Methods ========================================================================================================

    @Override
    public void afterPropertiesSet() throws Exception {
        super.afterPropertiesSet();
        Assert.notNull(configuration, "configuration cannot be null.");
    }

    /**
     * Creates a LoginContext using the Configuration that was specified in
     * {@link #setConfiguration(Configuration)}.
     */
    @Override
    protected LoginContext createLoginContext(CallbackHandler handler) throws LoginException {
        return new LoginContext(getLoginContextName(), null, handler, getConfiguration());
    }

    protected Configuration getConfiguration() {
        return configuration;
    }

    /**
     * Sets the Configuration to use for Authentication. 
     * 
     * @param configuration
     *            the Configuration that is used when
     *            {@link #createLoginContext(CallbackHandler)} is called.
     */
    public void setConfiguration(Configuration configuration) {
        this.configuration = configuration;
    }
}
