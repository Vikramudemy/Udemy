package com.javainfinite.users.ms.UserMS.security;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.javainfinite.users.ms.UserMS.service.UserService;

@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

	@Autowired
	Environment env;
	
	@Autowired
	private UserService usersService;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	

	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable(); // JWT token for user authorization - so disabling it
		http.authorizeRequests().antMatchers(HttpMethod.POST,"/**").hasIpAddress(env.getProperty("gateway.ip")).and()
				.addFilter(getAuthenticationFilter());
		http.headers().frameOptions().disable();

	}

	private AuthenticationFilter getAuthenticationFilter() throws Exception {
		System.out.println("Within getAuthenticationFilter - WebSecurity");
		AuthenticationFilter authenticationFilter = new AuthenticationFilter(usersService, env, authenticationManager());
		/*
		 * Why we are setting it here? --> in AuthenticationFilter class, we are using
		 * getAuthenticationManager() method directly..without setting it we will get
		 * error..so setting it here
		 */
		//authenticationFilter.setAuthenticationManager(authenticationManager());
		authenticationFilter.setFilterProcessesUrl(env.getProperty("login.url.path"));
		System.out.println("outside getAuthenticationFilter - WebSecurity");
		return authenticationFilter;
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder authBuilder) throws Exception {
		authBuilder.userDetailsService(usersService).passwordEncoder(bCryptPasswordEncoder);
		
	}

}
