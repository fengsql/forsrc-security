package com.forsrc.security.base;

import org.springframework.security.core.userdetails.UserDetails;

public interface IUserDetails extends UserDetails {

  BLoginResponse getLoginResponse();

  void setLoginResponse(BLoginResponse loginResponse);

}
