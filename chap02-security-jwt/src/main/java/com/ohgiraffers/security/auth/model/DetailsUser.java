package com.ohgiraffers.security.auth.model;

import com.ohgiraffers.security.user.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

public class DetailsUser implements UserDetails {

    private User user;

    public DetailsUser() {
    }

    public DetailsUser(Optional<User> user) {
        this.user = user.get();
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        user.getRoleList().forEach(role -> authorities.add(() -> role));

        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getUserPass();
    }

    @Override
    public String getUsername() {
        return user.getUserId();
    }

    /**
     * 계정 만료 여부
     * */
    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    /**
     * 잠긴 계정 확인
     * */
    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    /**
     * 탈퇴 계정 여부를 표현함
     * */
    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    /**
     * 계정 비활성화 여부
     * */
    @Override
    public boolean isEnabled() {
        return false;
    }

    // 세션 시큐리티에 자세한 설명 써있음
}
