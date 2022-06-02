package com.forsrc.security.model;

import com.forsrc.security.base.BLoginResponse;
import com.forsrc.security.base.IUserDetails;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Data
@EqualsAndHashCode(callSuper = false)
public class UserDetail implements IUserDetails {

  private int userId;

  private int roleType;

  private String username;

  private String password;

  private Collection<? extends GrantedAuthority> authorities;

  private BLoginResponse loginResponse;

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return authorities;
  }

  /**
   * 账户是否过期
   */
  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  /**
   * 是否禁用
   */
  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  /**
   * 密码是否过期
   */
  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  /**
   * 是否启用
   */
  @Override
  public boolean isEnabled() {
    return true;
  }
}