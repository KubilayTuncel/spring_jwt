package com.tpe.security;

import com.tpe.security.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
                                    throws ServletException, IOException {
        String jwtToken = parseJwt(request);

        try {
            if (jwtToken !=null && jwtUtils.valideToken(jwtToken)) {

              String userName =  jwtUtils.getUserNameFromJwtToken(jwtToken);
              UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

              //bu alttaki 4 satirda authentication builder dan security context e user i göndermis oluyoruz
                UsernamePasswordAuthenticationToken authentication=
                        new UsernamePasswordAuthenticationToken(
                                userDetails,null,userDetails.getAuthorities());

                SecurityContextHolder.getContext().setAuthentication(authentication);

            }
        } catch (UsernameNotFoundException e) {
            e.printStackTrace();
        }

        //bu satira ekliyoruz ki aksi takdirde security kismina ekleme islemini yapmaz.
        filterChain.doFilter(request,response);

    }

    private String parseJwt(HttpServletRequest request) {
       String header = request.getHeader("Authorizazion");
       if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
           return header.substring(7);
       }

       return null;
    }


    //istedigimiz bazi entpointleri security katmanina girmeden kullanici bu sayfalari acabilsin.
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        AntPathMatcher antPathMatcher = new AntPathMatcher();

        return antPathMatcher.match("/register",request.getServletPath()) ||
                antPathMatcher.match("/login", request.getServletPath());
    }
}
