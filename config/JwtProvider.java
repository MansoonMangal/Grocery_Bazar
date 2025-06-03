package com.groceryBazar.config;

import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.swing.Spring;

import org.aspectj.apache.bcel.classfile.Module.Uses;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtProvider {
	
	private SecretKey key=Keys.hmacShaKeyFor(JwtConstant.SECRET_KEY.getBytes());
	

	public String generateToken(Authentication auth) 
	{
		Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
	    String roles = populateAuthorities(authorities);

		String jwt=Jwts.builder()
				.setIssuedAt(new Date())
				.setExpiration(new Date(new Date().getTime()+86400000))
				.claim("email",auth.getName())
				.claim("authorities", roles)
				.signWith(key)
				.compact();

		return jwt;
	}

// 	//Collection<> → This is a Java interface that represents a group of elements (like a list or a set).

// <? extends GrantedAuthority> → This is a wildcard generic type, meaning the collection can hold any object that is a subclass of GrantedAuthority.

// GrantedAuthority → This is an interface in Spring Security that represents a user’s role/authority (e.g., "ROLE_ADMIN", "ROLE_USER").

// auth.getAuthorities() → This retrieves the list of authorities (roles) assigned to the authenticated user (auth is an Authentication object).

	
	public String getEmailFromJwtToken(String jwt) {
		jwt=jwt.substring(7);
		
		Claims claims=Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwt).getBody();
		String email=String.valueOf(claims.get("email"));
		
		return email;
	}

  //Claims is an interface from the io.jsonwebtoken package.
	//Stores the extracted claims (data) from the JWT.

// Claims claims	Stores the extracted user data from the JWT.
// Jwts.parserBuilder()	Creates a JWT parser to decode the token.
// .setSigningKey(key)	Uses the secret key to verify the token.
// .build()	Finalizes the JWT parser.
// .parseClaimsJws(jwt)	Parses & validates the JWT.
// .getBody()	Retrieves the payload (user data).
	
	public String populateAuthorities(Collection<? extends GrantedAuthority> collection) {
		Set<String> auths=new HashSet<>();
		
		for(GrantedAuthority authority:collection) {
			auths.add(authority.getAuthority());
		}
		return String.join(",",auths);
	}

	//This method converts the list of authorities into a comma-separated string of roles.

}
