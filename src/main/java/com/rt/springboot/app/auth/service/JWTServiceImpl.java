package com.rt.springboot.app.auth.service;

import java.io.IOException;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rt.springboot.app.auth.SimpleGrantedAuthorityMixin;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JWTServiceImpl implements JWTService {

	public static final Key SECRET_KEY = new SecretKeySpec("YWxndW5hTGxhdmVTZWNyZXRhQmFzZTY0".getBytes(), SignatureAlgorithm.HS512.getJcaName());
	public static final long EXPIRATION_DATE = 3600000*4L;
	public static final String TOKEN_PREFIX = "Bearer ";
	public static final String HEADER_PREFIX = "Authorization";
	
	@Override
	public String create(Authentication auth) throws IOException {
		
		Collection<? extends GrantedAuthority> roles =  auth.getAuthorities();

		Claims claims = Jwts.claims();
		claims.put("authorities", new ObjectMapper().writeValueAsString(roles));
		
		String token = Jwts.builder()
				.setClaims(claims)
				.setSubject(auth.getName())
				.signWith(SECRET_KEY)
				.setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_DATE))
				.compact();
		
		return token;
	}

	@Override
	public boolean validate(String token) {

		try {
			getClaims(token);
			return true;
			
		} catch (JwtException | IllegalArgumentException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public Claims getClaims(String token) {
		Claims claims = Jwts
				.parserBuilder().setSigningKey(SECRET_KEY)
				.build()
				.parseClaimsJws(resolve(token))
				.getBody();
		return claims;
	}

	@Override
	public String getUsername(String token) {
		return getClaims(token).getSubject();
	}

	@Override
	public Collection<? extends GrantedAuthority> getRoles(String token) throws IOException {
		Object roles = getClaims(token).get("authorities");
		
		Collection<? extends GrantedAuthority> authorities = Arrays.asList(new ObjectMapper()
				.addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
				.readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));
		
		return authorities;
	}

	@Override
	public String resolve(String token) {
		if(token != null && token.startsWith(TOKEN_PREFIX)) {
			return token.replace(TOKEN_PREFIX, "");			
		}
		return null;
	}

}
