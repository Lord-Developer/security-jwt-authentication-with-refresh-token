package lord_dev.com.securityjwtauthenticationwithrefreshtoken.models;

import java.util.Arrays;

public enum ERole {
//  ROLE_USER,
//  ROLE_MODERATOR,
//  ROLE_ADMIN


  ROLE_USER("ROLE_USER"),
  ROLE_MODERATOR("ROLE_MODERATOR"),
  ROLE_ADMIN("ROLE_ADMIN");
  private String roleName;

  public String getRoleName() {
    return roleName;
  }

  ERole(String roleName) {
    this.roleName = roleName;
  }

  public static final ERole getByValue(String value){
    return Arrays.stream(ERole.values()).filter(enumRole -> enumRole.roleName.equals(value)).findFirst().orElse(ROLE_USER);
  }

}
