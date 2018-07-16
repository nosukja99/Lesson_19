package com.example.demo;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.naming.AuthenticationException;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter{

    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        http
                .authorizeRequests()
                .antMatchers("/")
                .access("hasAnyAuthority('USER', 'ADMIN')")
                .antMatchers("/admin")
                .access("hasAnyAuthority('ADMIN')")
                .anyRequest().authenticated()
                .and()
                .formLogin().loginPage("/login").permitAll()
                .and()
                .httpBasic();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception
    {
        PasswordEncoder p = new BCryptPasswordEncoder();
        auth.inMemoryAuthentication()
                .withUser("user").password(p.encode("password")).authorities("USER")
                .and()
                .withUser("dave").password(p.encode("begreat")).authorities("ADMIN")
                .and()
                .passwordEncoder(new BCryptPasswordEncoder());
    }

   // @SuppressWarnings("deprecation")
  //  @Bean
   // public static NoOpPasswordEncoder passwordEncoder()
   // {
    //    return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    //}
}
