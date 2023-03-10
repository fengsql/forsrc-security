package com.forsrc.security.tool;

import com.forsrc.common.constant.Code;
import com.forsrc.common.exception.CommonException;
import com.forsrc.common.tool.Tool;
import com.forsrc.security.config.ConfigSecurity;
import com.forsrc.security.model.AuthenticationToken;
import com.forsrc.security.model.UserDetail;
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
  //
  private static final long expire_default = 3600L; //缺省过期时间，3600秒
  /**
   * 用户名称
   */
  private static final String USERNAME = Claims.SUBJECT;
  private static final String USERID = "userId";
  private static final String ROLE = "role";
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
   * 生成令牌。
   * @param authentication 认证信息。
   * @return 令牌。
   */
  public static String generateToken(Authentication authentication) {
    Map<String, Object> claims = new HashMap<>(5);
    UserDetail userDetail = ToolSecurity.getUserDetail(authentication);
    claims.put(USERID, userDetail.getUserId());
    claims.put(USERNAME, userDetail.getUsername());
    claims.put(ROLE, userDetail.getRoleType());
    claims.put(CREATED, new Date());
    claims.put(AUTHORITIES, authentication.getAuthorities());
    return generateToken(claims);
  }

  /**
   * 根据请求令牌获取授权信息。
   * @param request 请求。
   * @return 授权信息。
   */
  public static Authentication getAuthenticationFromToken(HttpServletRequest request) {
    String token = getToken(request);
    if (token == null) {
      //      throw new ErrorException(Code.AUTHENTICATION_EXCEPTION);
      return null;
    }
    return newAuthentication(token);
  }

  /**
   * 验证令牌。
   * @param token    令牌。
   * @param username 用户名。
   * @return true 有效，false 无效。
   */
  public static Boolean validateToken(String token, String username) {
    String userName = getUsernameFromToken(token);
    return userName != null && userName.equals(username);
  }

  /**
   * 刷新令牌。
   * @param token 令牌。
   * @return 新的令牌。
   */
  public static String refreshToken(String token) {
    String refreshedToken;
    try {
      Claims claims = getClaimsFromToken(token);
      if (claims == null) {
        return null;
      }
      claims.put(CREATED, new Date());
      refreshedToken = generateToken(claims);
    } catch (Exception e) {
      refreshedToken = null;
    }
    return refreshedToken;
  }

  /**
   * 判断令牌是否过期。
   * @param token 令牌
   * @return true 过期，false 未过期。
   */
  public static Boolean isTokenExpired(String token) {
    try {
      Claims claims = getClaimsFromToken(token);
      if (claims == null) {
        return true;
      }
      Date expiration = claims.getExpiration();
      return expiration.before(new Date());
    } catch (Exception e) {
      return true;
    }
  }

  private static String getToken(HttpServletRequest request) {
    String token = request.getHeader(AUTHORIZATION);
    if (token == null) {
      token = request.getHeader(TOKEN);
    } else if (token.startsWith(BEARER)) {
      token = token.substring(BEARER.length());
    }
    if ("".equals(token)) {
      token = null;
    }
//    log.info("getToken token: {}", token);
    return token;
  }

  private static Authentication newAuthentication(String token) {
    UserDetail userDetails = getUserDetailsFromToken(token);
    if (userDetails == null) {
      return null;
    }
    //    log.info("userDetails: {}", ToolJson.toJson(userDetails));
    return new AuthenticationToken(userDetails, null, userDetails.getAuthorities(), token);
  }

  private static UserDetail getUserDetailsFromToken(String token) {
    Claims claims = getClaimsFromToken(token);
    if (claims == null) {
      return null;
    }
    String username = claims.getSubject();
    if (username == null) {
      return null;
    }
    Object userId = claims.get(USERID);
    int roleType = Tool.toInt(claims.get(ROLE));
    Object authors = claims.get(AUTHORITIES);
    List<GrantedAuthority> authorities = new ArrayList<>();
    if (authors instanceof List) {
      for (Object object : (List) authors) {
        authorities.add(new SimpleGrantedAuthority((String) ((Map) object).get(AUTHORITY)));
      }
    }
    UserDetail userDetails = new UserDetail();
    userDetails.setUserId(userId);
    userDetails.setRoleType(roleType);
    userDetails.setUsername(username);
    //    userDetails.setPassword(passwordEncoder.encode(user.getPassword()));
    userDetails.setAuthorities(authorities);
    return userDetails;
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
      claims = null;
      //      throw new ErrorException(Code.AUTHENTICATION_EXCEPTION);
    }
    return claims;
  }

  /**
   * 从数据声明生成令牌
   * @param claims 数据声明
   * @return 令牌
   */
  private static String generateToken(Map<String, Object> claims) {
    long expire = getExpire();
    Date expirationDate = new Date(System.currentTimeMillis() + expire);
    String secret = ConfigSecurity.security.token.secret;
    return Jwts.builder().setClaims(claims).setExpiration(expirationDate).signWith(SignatureAlgorithm.HS512, secret).compact();
  }

  private static long getExpire() {
    String expire = ConfigSecurity.security.token.expire;
    Long value = Tool.getConfigTime(expire);
    if (Tool.isNull(value)) {
      value = expire_default;
    }
    if (value < 0) {
      throw new CommonException(Code.SETTING_ERROR, "时间配置无效! expire: " + expire);
    }
    return value * 1000L;
  }

  /**
   * 从令牌中获取用户名
   * @param token 令牌
   * @return 用户名
   */
  private static String getUsernameFromToken(String token) {
    String username;
    try {
      Claims claims = getClaimsFromToken(token);
      if (claims == null) {
        return null;
      }
      username = claims.getSubject();
    } catch (Exception e) {
      username = null;
    }
    return username;
  }

}