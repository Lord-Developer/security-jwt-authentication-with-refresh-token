package lord_dev.com.securityjwtauthenticationwithrefreshtoken.controllers;


import lord_dev.com.securityjwtauthenticationwithrefreshtoken.payload.request.LogOutRequest;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.payload.request.LoginRequest;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.payload.request.SignUpRequest;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.payload.request.TokenRefreshRequest;
import lord_dev.com.securityjwtauthenticationwithrefreshtoken.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
  @Autowired
  AuthService authService;

  @PostMapping("/sign_in")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
    return ResponseEntity.ok(authService.login(loginRequest));
  }

  @PostMapping("/sign_up")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
    return ResponseEntity.ok(authService.register(signUpRequest));
  }

  @PostMapping("/refresh_token")
  public ResponseEntity<?> refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
    return ResponseEntity.ok(authService.refreshToken(request));

  }

  @PostMapping("/logout")
  public ResponseEntity<?> logoutUser(@Valid @RequestBody LogOutRequest logOutRequest) {
    return ResponseEntity.ok(authService.logout(logOutRequest));

  }

}
