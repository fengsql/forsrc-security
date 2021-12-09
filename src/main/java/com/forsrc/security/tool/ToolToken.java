package com.forsrc.security.tool;

import com.forsrc.security.config.ConfigSecurity;
import com.forsrc.security.model.AuthenticationToken;
import com.forsrc.security.model.SecurityUserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.*;

@Slf4j
public class ToolToken implements Serializable {

  private static final long serialVersionUID = 1L;

  /**
   * 用户名称
   */
  private static final String USERNAME = Claims.SUBJECT;
  /**
   * 创建时间
   */
  private static final String CREATED = "created";
  /**
   * 权限列表
   */
  private static final String AUTHORITIES = "authorities";
  private static final String AUTHORITY = "authority";
  private static final String AUTHORIZATION = "Authorization";
  private static final String TOKEN = "token";
  private static final String BEARER = "Bearer ";

  /**
   * 生成令牌
   * @return 令牌
   */
  public static String generateToken(Authentication authentication) {
    Map<String, Object> claims = new HashMap<>(3);
    claims.put(USERNAME, ToolSecurity.getUsername(authentication));
    claims.put(CREATED, new Date());
    claims.put(AUTHORITIES, authentication.getAuthorities());
    return generateToken(claims);
  }

  /**
   * 从数据声明生成令牌
   * @param claims 数据声明
   * @return 令牌
   */
  private static String generateToken(Map<String, Object> claims) {
    long expire = ConfigSecurity.security.token.expire * 1000;
    Date expirationDate = new Date(System.currentTimeMillis() + expire);
    String secret = ConfigSecurity.security.token.secret;
    return Jwts.builder().setClaims(claims).setExpiration(expirationDate).signWith(SignatureAlgorithm.HS512, secret).compact();
  }

  /**
   * 从令牌中获取用户名
   * @param token 令牌
   * @return 用户名
   */
  public static String getUsernameFromToken(String token) {
    String username;
    try {
      Claims claims = getClaimsFromToken(token);
      username = claims.getSubject();
    } catch (Exception e) {
      username = null;
    }
    return username;
  }

  /**
   * 根据请求令牌获取登录认证信息
   * @return 用户名
   */
  public static Authentication getAuthenticationFromToken(HttpServletRequest request) {
    String token = getToken(request);
    if (token == null) {
      return null;
    }
    Authentication authentication = ToolSecurity.getAuthentication();
    if (authentication == null) {
      return getAuthenticationFromToken(token);
    }
    String username = ToolSecurity.getUsername(authentication);
    if (validateToken(token, username)) {
      return authentication;
    } else {
      return null;
    }
  }

  private static Authentication getAuthenticationFromToken(String token) {
    Claims claims = getClaimsFromToken(token);
    if (claims == null) {
      return null;
    }
    String username = claims.getSubject();
    if (username == null) {
      return null;
    }
    //    if (isTokenExpired(token)) {
    //      return null;
    //    }
    Object authors = claims.get(AUTHORITIES);
    List<GrantedAuthority> authorities = new ArrayList<>();
    if (authors instanceof List) {
      for (Object object : (List) authors) {
        authorities.add(new SimpleGrantedAuthority((String) ((Map) object).get(AUTHORITY)));
      }
    }
    SecurityUserDetails userDetails = new SecurityUserDetails();
    userDetails.setUsername(username);
    //    userDetails.setPassword(passwordEncoder.encode(user.getPassword()));
    userDetails.setAuthorities(authorities);
    Authentication authentication = new AuthenticationToken(userDetails, null, authorities, token);
    return authentication;
  }

  /**
   * 从令牌中获取数据声明
   * @param token 令牌
   * @return 数据声明
   */
  private static Claims getClaimsFromToken(String token) {
    Claims claims;
    try {
      String secret = ConfigSecurity.security.token.secret;
      claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    } catch (Exception e) {
      log.error("getClaimsFromToken error!", e);
      claims = null;
    }
    return claims;
  }

  /**
   * 验证令牌
   */
  public static Boolean validateToken(String token, String username) {
    String userName = getUsernameFromToken(token);
    return userName != null && userName.equals(username);
  }

  /**
   * 刷新令牌
   */
  public static String refreshToken(String token) {
    String refreshedToken;
    try {
      Claims claims = getClaimsFromToken(token);
      claims.put(CREATED, new Date());
      refreshedToken = generateToken(claims);
    } catch (Exception e) {
      refreshedToken = null;
    }
    return refreshedToken;
  }

  /**
   * 判断令牌是否过期
   * @param token 令牌
   * @return 是否过期
   */
  public static Boolean isTokenExpired(String token) {
    try {
      Claims claims = getClaimsFromToken(token);
      Date expiration = claims.getExpiration();
      return expiration.before(new Date());
    } catch (Exception e) {
      return false;
    }
  }

  /**
   * 获取请求token
   */
  public static String getToken(HttpServletRequest request) {
    String token = request.getHeader(AUTHORIZATION);
    String tokenHead = BEARER;
    if (token == null) {
      token = request.getHeader(TOKEN);
    } else if (token.contains(tokenHead)) {
      token = token.substring(tokenHead.length());
    }
    if ("".equals(token)) {
      token = null;
    }
    return token;
  }

}