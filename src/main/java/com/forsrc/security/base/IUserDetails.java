package com.forsrc.security.base;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public interface IUserDetails extends UserDetails {

  BLoginResponse getLoginResponse();

  void setLoginResponse(BLoginResponse loginResponse);

  void setAuthorities(Collection<? extends GrantedAuthority> authorities);

}
