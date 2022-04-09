package com.forsrc.security.tool;

import com.forsrc.security.model.SecurityUserDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import javax.servlet.http.HttpServletRequest;

@Slf4j
public class ToolSecurity {

  /**
   * 获取令牌进行认证
   */
  public static void setAuthentication(HttpServletRequest request) {
    Authentication authentication = ToolToken.getAuthenticationFromToken(request); // 获取令牌并根据令牌获取登录认证信息
    SecurityContextHolder.getContext().setAuthentication(authentication); // 设置登录认证信息到上下文
  }

  /**
   * 获取当前用户名
   */
  public static SecurityUserDetails getUserDetails(HttpServletRequest request) {
    SecurityUserDetails userDetails = ToolToken.getUserDetails(request);
    if (userDetails != null) {
      return userDetails;
    }
    Authentication authentication = ToolToken.getAuthenticationFromToken(request);
    return getUserDetails(authentication);
  }

  /**
   * 获取当前用户名
   */
  public static String getUsername(HttpServletRequest request) {
    Authentication authentication = ToolToken.getAuthenticationFromToken(request);
    return getUsername(authentication);
  }

  public static String getUsername() {
    Authentication authentication = getAuthentication();
    return getUsername(authentication);
  }

  /**
   * 获取用户名
   */
  public static String getUsername(Authentication authentication) {
    if (authentication == null) {
      return null;
    }
    Object principal = authentication.getPrincipal();
    if (principal instanceof UserDetails) {
      return ((UserDetails) principal).getUsername();
    }
    return null;
  }

  /**
   * 获取用户名
   */
  public static SecurityUserDetails getUserDetails(Authentication authentication) {
    if (authentication == null) {
      return null;
    }
    Object principal = authentication.getPrincipal();
    if (principal instanceof SecurityUserDetails) {
      return (SecurityUserDetails) principal;
    }
    return null;
  }

  /**
   * 获取当前登录信息
   */
  public static Authentication getAuthentication() {
    if (SecurityContextHolder.getContext() == null) {
      return null;
    }
    SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//    log.info("getAuthentication authentication: {}", authentication);
    return authentication;
  }

}
