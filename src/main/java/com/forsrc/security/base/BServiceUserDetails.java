package com.forsrc.security.base;

import com.forsrc.security.model.UserDetail;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Slf4j
public abstract class BServiceUserDetails<T> implements IServiceUserDetails {

  /**
   * 使用用户信息 user 填充用户对象 userDetails。
   * @param userDetails 用户对象。
   * @param user        用户信息。
   */
  protected abstract void setUserDetails(IUserDetails userDetails, T user);

  /**
   * 获取用户角色。
   * @param user 用户信息。
   * @return 返回用户角色列表。
   */
  protected abstract List<String> getRoles(T user);

  /**
   * 获取用户对象。
   * @param user 用户信息。
   * @return 返回用户对象。
   */
  protected final IUserDetails getUserDetails(T user) {
    IUserDetails userDetail = createUserDetails();
    setUserDetails(userDetail, user);
    userDetail.setLoginResponse(getLoginResponse(user));
    userDetail.setAuthorities(getAuthorities(user));
    return userDetail;
  }

  /**
   * 创建用户信息，默认使用 UserDetail，可以使用自定义用户对象覆盖此方法。
   * @return 返回用户对象。
   */
  protected IUserDetails createUserDetails() {
    return new UserDetail();
  }

  /**
   * 返回登录信息，可以使用自定义登录信息覆盖此方法。
   * @return 返回用户对象。
   */
  protected BLoginResponse getLoginResponse(T user) {
    return new BLoginResponse();
  }

  private Collection<? extends GrantedAuthority> getAuthorities(T user) {
    List<String> list = getRoles(user);
    if (list == null) {
      list = new ArrayList<>();
    }
    return AuthorityUtils.createAuthorityList(list.toArray(new String[0]));
  }
}