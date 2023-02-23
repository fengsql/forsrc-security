package com.forsrc.security.handler;

import com.forsrc.common.constant.Code;
import com.forsrc.common.constant.Const;
import com.forsrc.common.exception.CommonException;
import com.forsrc.common.tool.Tool;
import com.forsrc.common.tool.ToolJson;
import com.forsrc.security.config.ConfigSecurity;
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
    checkLoginUser(loginUser, param);
    checkVerifyCode(request, loginUser);
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

  private void checkLoginUser(LoginUser loginUser, String param) {
    if (loginUser == null) {
      log.warn("login fail! loginUser is null. param: {}", param);
      throw new CommonException(Code.USER_LOGIN_FAIL, "login param error!");
    }
    if (Tool.isNull(loginUser.getUsername())) {
      log.warn("login fail! username is null. param: {}", param);
      throw new CommonException(Code.USER_LOGIN_FAIL, "username or password is empty!");
    }
    if (Tool.isNull(loginUser.getPassword())) {
      log.warn("login fail! password is null. param: {}", param);
      throw new CommonException(Code.USER_LOGIN_FAIL, "username or password is empty!");
    }
  }

  private void checkVerifyCode(HttpServletRequest request, LoginUser loginUser) {
    if (!ConfigSecurity.security.enableVerifyCode) {
      return;
    }
    String verifyCode = loginUser.getVerifyCode();
    if (Tool.isNull(verifyCode)) {
      throw new CommonException(Code.USER_LOGIN_FAIL, "request verifyCode is empty!");
    }
    String code = (String) request.getSession().getAttribute(Const.param_verifyCode);
    if (Tool.isNull(code)) {
      throw new CommonException(Code.USER_LOGIN_FAIL, "attribute verifyCode is empty!");
    }
    if (!verifyCode.trim().toLowerCase().equals(code.toLowerCase())) {
      throw new CommonException(Code.USER_LOGIN_FAIL, "verifyCode not match!");
    }
  }

}
