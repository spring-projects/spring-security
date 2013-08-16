package org.springframework.security.samples.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.samples.security.CustomUserDetailsService;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/user/**").hasRole("ADMIN")
                .antMatchers("/resources/**").permitAll()
                .anyRequest().authenticated()
                .and()
            .openidLogin()
                .permitAll()
                .authenticationUserDetailsService(new CustomUserDetailsService())
                .attributeExchange("https://www.google.com/.*")
                    .attribute("email")
                        .type("http://axschema.org/contact/email")
                        .required(true)
                        .and()
                    .attribute("firstname")
                        .type("http://axschema.org/namePerson/first")
                        .required(true)
                        .and()
                    .attribute("lastname")
                        .type("http://axschema.org/namePerson/last")
                        .required(true)
                        .and()
                    .and()
                .attributeExchange(".*yahoo.com.*")
                    .attribute("email")
                        .type("http://axschema.org/contact/email")
                        .required(true)
                        .and()
                    .attribute("fullname")
                        .type("http://axschema.org/namePerson")
                        .required(true)
                        .and()
                    .and()
                .attributeExchange(".*myopenid.com.*")
                    .attribute("email")
                        .type("http://schema.openid.net/contact/email")
                        .required(true)
                        .and()
                    .attribute("fullname")
                        .type("http://schema.openid.net/namePerson")
                        .required(true);
    }
}
