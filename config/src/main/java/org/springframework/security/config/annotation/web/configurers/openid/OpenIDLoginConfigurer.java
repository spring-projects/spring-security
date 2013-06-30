/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.config.annotation.web.configurers.openid;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.RememberMeConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.annotation.web.configurers.openid.OpenIDLoginConfigurer;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.openid.AxFetchListFactory;
import org.springframework.security.openid.OpenID4JavaConsumer;
import org.springframework.security.openid.OpenIDAttribute;
import org.springframework.security.openid.OpenIDAuthenticationFilter;
import org.springframework.security.openid.OpenIDAuthenticationProvider;
import org.springframework.security.openid.OpenIDAuthenticationToken;
import org.springframework.security.openid.OpenIDConsumer;
import org.springframework.security.openid.RegexBasedAxFetchListFactory;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.ui.DefaultLoginPageViewFilter;

/**
 * Adds support for OpenID based authentication.
 *
 * <h2>Example Configuration</h2>
 *
 * <pre>
 *
 * &#064;Configuration
 * &#064;EnableWebSecurity
 * public class OpenIDLoginConfig extends WebSecurityConfigurerAdapter {
 *
 * 	&#064;Override
 * 	protected void configure(HttpSecurity http) {
 * 		http
 * 			.authorizeUrls()
 * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
 * 				.and()
 * 			.openidLogin()
 * 				.permitAll();
 * 	}
 *
 * 	&#064;Override
 * 	protected void registerAuthentication(
 * 			AuthenticationManagerBuilder auth) throws Exception {
 * 		auth
 * 			.inMemoryAuthentication()
 * 				.withUser(&quot;https://www.google.com/accounts/o8/id?id=lmkCn9xzPdsxVwG7pjYMuDgNNdASFmobNkcRPaWU&quot;)
 * 					.password(&quot;password&quot;)
 * 					.roles(&quot;USER&quot;);
 * 	}
 * }
 * </pre>
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>
 * {@link OpenIDAuthenticationFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * <ul>
 * <li>
 * {@link AuthenticationEntryPoint}
 * is populated with a {@link LoginUrlAuthenticationEntryPoint}</li>
 * <li>A {@link OpenIDAuthenticationProvider} is populated into
 * {@link HttpSecurity#authenticationProvider(org.springframework.security.authentication.AuthenticationProvider)}
 * </li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link HttpSecurity#getAuthenticationManager()}</li>
 * <li>{@link RememberMeServices} - is optionally used. See
 * {@link RememberMeConfigurer}</li>
 * <li>{@link SessionAuthenticationStrategy} - is optionally used. See
 * {@link SessionManagementConfigurer}</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class OpenIDLoginConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractAuthenticationFilterConfigurer<H,OpenIDLoginConfigurer<H>,OpenIDAuthenticationFilter> {
    private OpenIDConsumer openIDConsumer;
    private ConsumerManager consumerManager;
    private AuthenticationUserDetailsService<OpenIDAuthenticationToken> authenticationUserDetailsService;
    private List<AttributeExchangeConfigurer> attributeExchangeConfigurers = new ArrayList<AttributeExchangeConfigurer>();

    /**
     * Creates a new instance
     */
    public OpenIDLoginConfigurer() {
        super(new OpenIDAuthenticationFilter(),"/login/openid");
    }

    /**
     * Sets up OpenID attribute exchange for OpenID's matching the specified
     * pattern.
     *
     * @param identifierPattern
     *            the regular expression for matching on OpenID's (i.e.
     *            "https://www.google.com/.*", ".*yahoo.com.*", etc)
     * @return a {@link AttributeExchangeConfigurer} for further customizations of the attribute exchange
     */
    public AttributeExchangeConfigurer attributeExchange(String identifierPattern) {
        AttributeExchangeConfigurer attributeExchangeConfigurer = new AttributeExchangeConfigurer(identifierPattern);
        this.attributeExchangeConfigurers .add(attributeExchangeConfigurer);
        return attributeExchangeConfigurer;
    }

    /**
     * Allows specifying the {@link OpenIDConsumer} to be used. The default is
     * using an {@link OpenID4JavaConsumer}.
     *
     * @param consumer
     *            the {@link OpenIDConsumer} to be used
     * @return the {@link OpenIDLoginConfigurer} for further customizations
     */
    public OpenIDLoginConfigurer<H> consumer(OpenIDConsumer consumer) {
        this.openIDConsumer = consumer;
        return this;
    }

    /**
     * Allows specifying the {@link ConsumerManager} to be used. If specified,
     * will be populated into an {@link OpenID4JavaConsumer}.
     *
     * <p>
     * This is a shortcut for specifying the {@link OpenID4JavaConsumer} with a
     * specific {@link ConsumerManager} on {@link #consumer(OpenIDConsumer)}.
     * </p>
     *
     * @param consumerManager the {@link ConsumerManager} to use. Cannot be null.
     * @return the {@link OpenIDLoginConfigurer} for further customizations
     */
    public OpenIDLoginConfigurer<H> consumerManager(ConsumerManager consumerManager) {
        this.consumerManager = consumerManager;
        return this;
    }

    /**
     * The {@link AuthenticationUserDetailsService} to use. By default a
     * {@link UserDetailsByNameServiceWrapper} is used with the
     * {@link UserDetailsService} shared object found with
     * {@link HttpSecurity#getSharedObject(Class)}.
     *
     * @param authenticationUserDetailsService the {@link AuthenticationDetailsSource} to use
     * @return the {@link OpenIDLoginConfigurer} for further customizations
     */
    public OpenIDLoginConfigurer<H> authenticationUserDetailsService(AuthenticationUserDetailsService<OpenIDAuthenticationToken> authenticationUserDetailsService) {
        this.authenticationUserDetailsService = authenticationUserDetailsService;
        return this;
    }

    /**
     * Specifies the URL used to authenticate OpenID requests. If the {@link HttpServletRequest}
     * matches this URL the {@link OpenIDAuthenticationFilter} will attempt to
     * authenticate the request. The default is "/login/openid".
     *
     * @param loginUrl
     *            the URL used to perform authentication
     * @return the {@link OpenIDLoginConfigurer} for additional customization
     */
    public OpenIDLoginConfigurer<H> loginProcessingUrl(String loginProcessingUrl) {
        return super.loginProcessingUrl(loginProcessingUrl);
    }

    /**
     * <p>
     * Specifies the URL to send users to if login is required. If used with
     * {@link WebSecurityConfigurerAdapter} a default login page will be
     * generated when this attribute is not specified.
     * </p>
     *
     * <p>
     * If a URL is specified or this is not being used in conjuction with
     * {@link WebSecurityConfigurerAdapter}, users are required to process the
     * specified URL to generate a login page.
     * </p>
     *
     * <ul>
     * <li>It must be an HTTP POST</li>
     * <li>It must be submitted to {@link #loginProcessingUrl(String)}</li>
     * <li>It should include the OpenID as an HTTP parameter by the name of
     * {@link OpenIDAuthenticationFilter#DEFAULT_CLAIMED_IDENTITY_FIELD}</li>
     * </ul>
     *
     * @param loginPage the login page to redirect to if authentication is required (i.e. "/login")
     * @return the {@link FormLoginConfigurer} for additional customization
     */
    public OpenIDLoginConfigurer<H> loginPage(String loginPage) {
        return super.loginPage(loginPage);
    }

    @Override
    public void init(H http) throws Exception {
        super.init(http);

        OpenIDAuthenticationProvider authenticationProvider = new OpenIDAuthenticationProvider();
        authenticationProvider.setAuthenticationUserDetailsService(getAuthenticationUserDetailsService(http));
        authenticationProvider = postProcess(authenticationProvider);
        http.authenticationProvider(authenticationProvider);

        initDefaultLoginFilter(http);
    }

    @Override
    public void configure(H http) throws Exception {
        getAuthenticationFilter().setConsumer(getConsumer());
        super.configure(http);
    }

    /**
     * Gets the {@link OpenIDConsumer} that was configured or defaults to an {@link OpenID4JavaConsumer}.
     * @return the {@link OpenIDConsumer} to use
     * @throws ConsumerException
     */
    private OpenIDConsumer getConsumer() throws ConsumerException {
        if(openIDConsumer == null) {
            openIDConsumer = new OpenID4JavaConsumer(getConsumerManager(), attributesToFetchFactory());
        }
        return openIDConsumer;
    }

    /**
     * Gets the {@link ConsumerManager} that was configured or defaults to using a {@link ConsumerManager} with the default constructor.
     * @return the {@link ConsumerManager} to use
     */
    private ConsumerManager getConsumerManager() {
        if(this.consumerManager != null) {
            return this.consumerManager;
        }
        return new ConsumerManager();
    }

    /**
     * Creates an {@link RegexBasedAxFetchListFactory} using the attributes
     * populated by {@link AttributeExchangeConfigurer}
     *
     * @return the {@link AxFetchListFactory} to use
     */
    private AxFetchListFactory attributesToFetchFactory() {
        Map<String,List<OpenIDAttribute>> identityToAttrs = new HashMap<String,List<OpenIDAttribute>>();
        for(AttributeExchangeConfigurer conf : attributeExchangeConfigurers) {
            identityToAttrs.put(conf.identifier, conf.getAttributes());
        }
        return new RegexBasedAxFetchListFactory(identityToAttrs);
    }

    /**
     * Gets the {@link AuthenticationUserDetailsService} that was configured or
     * defaults to {@link UserDetailsByNameServiceWrapper} that uses a
     * {@link UserDetailsService} looked up using
     * {@link HttpSecurity#getSharedObject(Class)}
     *
     * @param http the current {@link HttpSecurity}
     * @return the {@link AuthenticationUserDetailsService}.
     */
    private AuthenticationUserDetailsService<OpenIDAuthenticationToken> getAuthenticationUserDetailsService(
            H http) {
        if(authenticationUserDetailsService != null) {
            return authenticationUserDetailsService;
        }
        return new UserDetailsByNameServiceWrapper<OpenIDAuthenticationToken>(http.getSharedObject(UserDetailsService.class));
    }

    /**
     * If available, initializes the {@link DefaultLoginPageViewFilter} shared object.
     *
     * @param http the {@link HttpSecurityBuilder} to use
     */
    private void initDefaultLoginFilter(H http) {
        DefaultLoginPageViewFilter loginPageGeneratingFilter = http.getSharedObject(DefaultLoginPageViewFilter.class);
        if(loginPageGeneratingFilter != null && !isCustomLoginPage()) {
            loginPageGeneratingFilter.setOpenIdEnabled(true);
            loginPageGeneratingFilter.setOpenIDauthenticationUrl(getLoginProcessingUrl());
            String loginPageUrl = loginPageGeneratingFilter.getLoginPageUrl();
            if(loginPageUrl == null) {
                loginPageGeneratingFilter.setLoginPageUrl(getLoginPage());
                loginPageGeneratingFilter.setFailureUrl(getFailureUrl());
            }
            loginPageGeneratingFilter.setOpenIDusernameParameter(OpenIDAuthenticationFilter.DEFAULT_CLAIMED_IDENTITY_FIELD);
        }
    }


    /**
     * A class used to add OpenID attributes to look up
     *
     * @author Rob Winch
     */
    public final class AttributeExchangeConfigurer {
        private final String identifier;
        private List<OpenIDAttribute> attributes = new ArrayList<OpenIDAttribute>();
        private List<AttributeConfigurer> attributeConfigurers = new ArrayList<AttributeConfigurer>();

        /**
         * Creates a new instance
         * @param identifierPattern the pattern that attempts to match on the OpenID
         * @see OpenIDLoginConfigurer#attributeExchange(String)
         */
        private AttributeExchangeConfigurer(String identifierPattern) {
            this.identifier = identifierPattern;
        }

        /**
         * Get the {@link OpenIDLoginConfigurer} to customize the OpenID configuration further
         * @return the {@link OpenIDLoginConfigurer}
         */
        public OpenIDLoginConfigurer<H> and() {
            return OpenIDLoginConfigurer.this;
        }

        /**
         * Adds an {@link OpenIDAttribute} to be obtained for the configured OpenID pattern.
         * @param attribute the {@link OpenIDAttribute} to obtain
         * @return the {@link AttributeExchangeConfigurer} for further customization of attribute exchange
         */
        public AttributeExchangeConfigurer attribute(OpenIDAttribute attribute) {
            this.attributes.add(attribute);
            return this;
        }

        /**
         * Adds an {@link OpenIDAttribute} with the given name
         * @param name the name of the {@link OpenIDAttribute} to create
         * @return an {@link AttributeConfigurer} to further configure the {@link OpenIDAttribute} that should be obtained.
         */
        public AttributeConfigurer attribute(String name) {
            AttributeConfigurer attributeConfigurer = new AttributeConfigurer(name);
            this.attributeConfigurers.add(attributeConfigurer);
            return attributeConfigurer;
        }

        /**
         * Gets the {@link OpenIDAttribute}'s for the configured OpenID pattern
         * @return
         */
        private List<OpenIDAttribute> getAttributes() {
            for(AttributeConfigurer config : attributeConfigurers) {
                attributes.add(config.build());
            }
            attributeConfigurers.clear();
            return attributes;
        }

        /**
         * Configures an {@link OpenIDAttribute}
         *
         * @author Rob Winch
         * @since 3.2
         */
        public final class AttributeConfigurer {
            private String name;
            private int count = 1;
            private boolean required = false;
            private String type;

            /**
             * Creates a new instance
             * @param name the name of the attribute
             * @see AttributeExchangeConfigurer#attribute(String)
             */
            private AttributeConfigurer(String name) {
                this.name = name;
            }

            /**
             * Specifies the number of attribute values to request. Default is 1.
             * @param count the number of attributes to request.
             * @return the {@link AttributeConfigurer} for further customization
             */
            public AttributeConfigurer count(int count) {
                this.count = count;
                return this;
            }

            /**
             * Specifies that this attribute is required. The default is
             * <code>false</code>. Note that as outlined in the OpenID
             * specification, required attributes are not validated by the
             * OpenID Provider. Developers should perform any validation in
             * custom code.
             *
             * @param required specifies the attribute is required
             * @return the {@link AttributeConfigurer} for further customization
             */
            public AttributeConfigurer required(boolean required) {
                this.required = required;
                return this;
            }

            /**
             * The OpenID attribute type.
             * @param type
             * @return
             */
            public AttributeConfigurer type(String type) {
                this.type = type;
                return this;
            }

            /**
             * Gets the {@link AttributeExchangeConfigurer} for further
             * customization of the attributes
             *
             * @return the {@link AttributeConfigurer}
             */
            public AttributeExchangeConfigurer and() {
                return AttributeExchangeConfigurer.this;
            }

            /**
             * Builds the {@link OpenIDAttribute}.
             * @return
             */
            private OpenIDAttribute build() {
                OpenIDAttribute attribute = new OpenIDAttribute(name, type);
                attribute.setCount(count);
                attribute.setRequired(required);
                return attribute;
            }
        }
    }
}
