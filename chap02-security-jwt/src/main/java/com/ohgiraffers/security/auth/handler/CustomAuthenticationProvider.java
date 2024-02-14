package com.ohgiraffers.security.auth.handler;

import com.ohgiraffers.security.auth.model.DetailsUser;
import com.ohgiraffers.security.auth.service.DetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private DetailsService detailsService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 1. username password Token(사용자가 로그인 요청시 날린 아이디와 비밀번호를 가지고 있는 임시 객체)
        UsernamePasswordAuthenticationToken loginToken = (UsernamePasswordAuthenticationToken) authentication; // 토큰화
        String username = loginToken.getName();
        String password = (String) loginToken.getCredentials(); // getCredentials: 토큰이 가지고 있는 값

        // 2. DB에서 username에 해당하는 정보를 조회한다.
        DetailsUser foundUser = (DetailsUser) detailsService.loadUserByUsername(username);
        // 자바의 상속에서 자식은 부모를 포함할 수 잇지만 부모는 자식을 포함하지 못한다
        if(!passwordEncoder.matches(password, foundUser.getPassword())){
            //passwordEncoder.matches는 password와 foundUser.getPassword가 같은지 비교한다
            throw new BadCredentialsException("password가 일치하지 않습니다.");
        }
        // 단방향 암호화는 복호화가 안되고 양방향은 복호화가 된다
        // 사용자가 입력한 username, password와 아이디의 비밀번호를 비교하는 로직을 수행함

        return new UsernamePasswordAuthenticationToken(foundUser.getUsername(), foundUser.getPassword(), foundUser.getAuthorities());
        // 권한 목록을 반환타입으로 지정해야됨
    }
    // 이 메서드가 하는 역할 : 사용자 정보를 조회한다음에 토큰값이랑 비교해줌

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
