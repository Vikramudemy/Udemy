package com.javainfinite.zuulapi.gateway.zuulapigateway.security;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMethod;

@Configuration
@EnableWebSecurity
public class WebSecurity1 extends WebSecurityConfigurerAdapter {

	@Autowired
	private Environment environment;

	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable(); // JWT token for user authorization - so disabling it
		http.headers().frameOptions().disable();
		http.authorizeRequests().antMatchers(HttpMethod.POST, environment.getProperty("login.url")).permitAll()
				.antMatchers(HttpMethod.POST, environment.getProperty("user.registration")).permitAll().anyRequest()
				.authenticated().and().addFilter(new AuthorizationFilter(authenticationManager(), environment));
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // to create a session of not -
																							// other options - Always,
																							// If Required, Never - will
																							// not create session but
																							// will use existing
																							// session, Stateless -
																							// never use session
	}
}
