package com.javainfinite.zuulapi.gateway.zuulapigateway.security;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Jwts;

public class AuthorizationFilter extends BasicAuthenticationFilter {

	Environment environment;

	public AuthorizationFilter(AuthenticationManager authenticationManager, Environment environment) {
		super(authenticationManager);
		this.environment=environment;
		// TODO Auto-generated constructor stub
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		System.out.println(environment.getProperty("authorization.token.header.name"));

		String authorization = request.getHeader(environment.getProperty("authorization.token.header.name"));

		if (authorization == null
				|| !authorization.startsWith(environment.getProperty("authorizaiton.token.header.prefix"))) {
			chain.doFilter(request, response);
			return;
		}

		UsernamePasswordAuthenticationToken token = getAuthorization(authorization);

		System.out.println("token: " + token);

		SecurityContextHolder.getContext().setAuthentication(token);
		chain.doFilter(request, response);

	}

	private UsernamePasswordAuthenticationToken getAuthorization(String authorization) {
		String token = authorization.replace(environment.getProperty("authorization.token.header.prefix"), "");
		System.out.println("Getting property: "+Jwts.parser().setSigningKey(environment.getProperty("token.secret")));
		System.out.println("Parsing Token: "+Jwts.parser().setSigningKey(environment.getProperty("token.secret")).parseClaimsJws(token));
		String userId = Jwts.parser().setSigningKey(environment.getProperty("token.secret")).parseClaimsJws(token)
				.getBody().getSubject();
		System.out.println("UserId: " + userId);
		return new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>());
	}

}
