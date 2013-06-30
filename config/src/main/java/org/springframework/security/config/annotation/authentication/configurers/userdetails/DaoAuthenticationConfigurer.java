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
package org.springframework.security.config.annotation.authentication.configurers.userdetails;

import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
* Allows configuring a {@link DaoAuthenticationProvider}
*
* @author Rob Winch
* @since 3.2
*
* @param <B> The type of {@link ProviderManagerBuilder} this is
* @param <U> The type of {@link UserDetailsService} that is being used
*
*/
public class DaoAuthenticationConfigurer<B extends ProviderManagerBuilder<B>, U extends UserDetailsService> extends AbstractDaoAuthenticationConfigurer<B,DaoAuthenticationConfigurer<B,U>, U>{

    /**
     * Creates a new instance
     * @param userDetailsService
     */
    public DaoAuthenticationConfigurer(U userDetailsService) {
        super(userDetailsService);
    }
}
