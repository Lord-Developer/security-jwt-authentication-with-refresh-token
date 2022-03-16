package lord_dev.com.securityjwtauthenticationwithrefreshtoken.service;


import lord_dev.com.securityjwtauthenticationwithrefreshtoken.exception.TokenRefreshException;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.models.ERole;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.models.RefreshToken;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.models.Role;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.models.User;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.payload.request.LogOutRequest;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.payload.request.LoginRequest;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.payload.request.SignUpRequest;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.payload.request.TokenRefreshRequest;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.payload.response.JwtResponse;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.payload.response.MessageResponse;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.payload.response.TokenRefreshResponse;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.repository.RoleRepository;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.repository.UserRepository;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.security.jwt.JwtUtils;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.security.services.RefreshTokenService;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AuthService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    RefreshTokenService refreshTokenService;

    public MessageResponse register(SignUpRequest signUpRequest){
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return new MessageResponse("Error: Username is already taken!");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return new MessageResponse("Error: Email is already in use!");
        }

        User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        }else{
            strRoles.forEach((role)->{

               roles.add(roleRepository
                        .findByName(ERole.getByValue(role))
                        .get());
            });
        }
        user.setRoles(roles);
        userRepository.save(user);
        return new MessageResponse("User registered successfully!");

    }


    public JwtResponse login(LoginRequest loginRequest){
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        String jwt = jwtUtils.generateJwtToken(userDetails);

        List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
                .collect(Collectors.toList());

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        return new JwtResponse(jwt, refreshToken.getToken(), userDetails.getId(),
                userDetails.getUsername(), userDetails.getEmail(), roles);
    }

    public MessageResponse logout(LogOutRequest logOutRequest){
        refreshTokenService.deleteByUserId(logOutRequest.getUserId());
        return new MessageResponse("Log out successful!");
    }

    public TokenRefreshResponse refreshToken(TokenRefreshRequest request){
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = jwtUtils.generateTokenFromUsername(user.getUsername());
                    return new TokenRefreshResponse(token, requestRefreshToken);
                })
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                        "Refresh token is not in database!"));
    }
}
