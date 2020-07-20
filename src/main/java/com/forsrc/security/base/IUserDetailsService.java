package com.forsrc.security.base;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface IUserDetailsService extends UserDetailsService {

  IUserDetails loadUserByUsername(String username) throws UsernameNotFoundException;

}
