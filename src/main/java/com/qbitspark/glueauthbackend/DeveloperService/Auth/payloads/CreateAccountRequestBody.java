package com.qbitspark.glueauthbackend.DeveloperService.Auth.payloads;

import com.qbitspark.glueauthbackend.DeveloperService.Auth.enums.AccountType;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enums.OrganizationSize;
import com.qbitspark.glueauthbackend.DeveloperService.Auth.enums.SocialProviders;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
public class CreateAccountRequestBody {

    @NotBlank(message = "Email is required")
    @Email(message = "Email must be valid")
    @Pattern(regexp = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$",
            message = "Email format is invalid")
    private String email;


    @Size(min = 8, message = "Password must be at least 8 characters")
    @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$",
            message = "Password must contain at least one digit, one lowercase, one uppercase, and one special character")
    private String password;


    private String accountName;

    @NotNull(message = "Account type is required")
    private AccountType accountType;

    private String organizationName;

    private OrganizationSize organizationSize;

    @Size(max = 255, message = "Profile picture URL exceeds maximum length")
    private String profilePictureUrl;

    //@Pattern(regexp = "^\\+?[0-9]{10,15}$", message = "Phone number format is invalid")
    private String phoneNumber;

    private SocialProviders socialAuthProvider;

    private String socialLoginId;

    // Validation logic for organizational account
    @AssertTrue(message = "Organization name is required for organization accounts")
    public boolean isOrganizationValid() {
        if (accountType == AccountType.ORGANIZATION) {
            return organizationName != null && !organizationName.trim().isEmpty() &&
                    organizationSize != null;
        }
        return true;
    }

}