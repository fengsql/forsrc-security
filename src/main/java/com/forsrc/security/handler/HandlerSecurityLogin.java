package com.forsrc.security.handler;

import com.forsrc.common.tool.Tool;
import com.forsrc.common.tool.ToolJson;
import com.forsrc.security.model.AuthenticationToken;
import com.forsrc.security.model.LoginUser;
import com.forsrc.security.model.UserDetail;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import javax.servlet.http.HttpServletRequest;

@Slf4j
public class HandlerSecurityLogin {
  @Setter
  private AuthenticationManager authenticationManager;

  @SneakyThrows
  public Authentication login(HttpServletRequest request) {
    String param = Tool.readStream(request.getInputStream());
    LoginUser loginUser = ToolJson.toBean(param, LoginUser.class);
    return login(request, loginUser);
  }

  private Authentication login(HttpServletRequest request, LoginUser loginUser) {
    UserDetails userDetails = getUserDetails(loginUser);
    AuthenticationToken authenticationToken = getAuthenticationToken(request, userDetails, loginUser);
    //验证登录，调用 loadUserByUsername 方法
    Authentication authentication = authenticationManager.authenticate(authenticationToken);
    SecurityContextHolder.getContext().setAuthentication(authentication);  // 认证成功存储认证信息到上下文
    return authentication;
  }

  private AuthenticationToken getAuthenticationToken(HttpServletRequest request, UserDetails userDetails, LoginUser loginUser) {
    AuthenticationToken authenticationToken = new AuthenticationToken(userDetails, loginUser.getPassword());
    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
    return authenticationToken;
  }

  private UserDetails getUserDetails(LoginUser loginUser) {
    UserDetail userDetail = new UserDetail();
    userDetail.setUsername(loginUser.getUsername());
    return userDetail;
  }

}
