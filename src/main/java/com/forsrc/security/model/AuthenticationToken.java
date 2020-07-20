package com.forsrc.security.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class AuthenticationToken extends UsernamePasswordAuthenticationToken {

  @Getter
  @Setter
  private String token;

  public AuthenticationToken(Object principal, Object credentials) {
    super(principal, credentials);
  }

  public AuthenticationToken(Object principal, Object credentials, String token) {
    super(principal, credentials);
    this.token = token;
  }

  public AuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities, String token) {
    super(principal, credentials, authorities);
    this.token = token;
  }

}
