package org.springframework.security.samples.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.samples.security.CustomUserDetailsService;

@Configuration
@EnableWebMvcSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/resources/**").permitAll()
                .anyRequest().authenticated()
                .and()
            .openidLogin()
                .loginPage("/login")
                .permitAll()
                .authenticationUserDetailsService(new CustomUserDetailsService())
                .attributeExchange("https://www.google.com/.*")
                    .attribute("email")
                        .type("https://axschema.org/contact/email")
                        .required(true)
                        .and()
                    .attribute("firstname")
                        .type("https://axschema.org/namePerson/first")
                        .required(true)
                        .and()
                    .attribute("lastname")
                        .type("https://axschema.org/namePerson/last")
                        .required(true)
                        .and()
                    .and()
                .attributeExchange(".*yahoo.com.*")
                    .attribute("email")
                        .type("https://axschema.org/contact/email")
                        .required(true)
                        .and()
                    .attribute("fullname")
                        .type("https://axschema.org/namePerson")
                        .required(true)
                        .and()
                    .and()
                .attributeExchange(".*myopenid.com.*")
                    .attribute("email")
                        .type("https://schema.openid.net/contact/email")
                        .required(true)
                        .and()
                    .attribute("fullname")
                        .type("https://schema.openid.net/namePerson")
                        .required(true);
    }
}
