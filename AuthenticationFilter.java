package com.javainfinite.users.ms.UserMS.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.javainfinite.users.ms.UserMS.model.LoginRequestModel;
import com.javainfinite.users.ms.UserMS.service.UserService;
import com.javainfinite.users.ms.UserMS.shared.UserDto;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	@Autowired
	private UserService userService;

	@Autowired
	private Environment environment;

	public AuthenticationFilter(UserService userService, Environment environment,
			AuthenticationManager authenticationManager) {
		this.userService = userService;
		this.environment = environment;
		super.setAuthenticationManager(authenticationManager);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res)
			throws AuthenticationException {

		try {
			System.out.println("Attempt Authentication inside");
			LoginRequestModel requestModel = new ObjectMapper().readValue(req.getInputStream(),
					LoginRequestModel.class);
			return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(
					requestModel.getEmail(), requestModel.getPassword(), new ArrayList<>()));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

	}

	/***
	 * This method will be called after performing authentication process, this will
	 * take user id or name or email (username for login) and will generate JWT
	 * token and add it to header of response and returns to the client
	 */
	@Override
	protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, FilterChain filter,
			Authentication auth) throws IOException, AuthenticationException {

		/*
		 * After successful authorization, we can get user name from authentication
		 * itself
		 */
		System.out.println("successfulAuthentication inside");
		String userName = ((User) auth.getPrincipal()).getUsername();
		UserDto userDto = userService.getUserDetailsByEmail(userName);
		System.out.println("User DTO data: " + userDto.getUserId());
		String token = Jwts.builder().setSubject(userDto.getUserId())
				.setExpiration(new Date(
						System.currentTimeMillis() + Long.parseLong(environment.getProperty("token.expiration_time"))))
				.signWith(SignatureAlgorithm.HS512, environment.getProperty("token.secret")).compact();
		res.addHeader("token", token);
		res.addHeader("userId", userDto.getUserId());

	}

}
