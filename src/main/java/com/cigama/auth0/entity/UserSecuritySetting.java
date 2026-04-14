package com.cigama.auth0.entity;

import jakarta.persistence.*;
import java.util.UUID;

@Entity
@Table(name = "user_security_settings")
public class UserSecuritySetting extends BaseAuditEntity {

    // --- Fields ---

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "require_otp_for_password", nullable = false)
    private Boolean requireOtpForPassword = false;

    @Column(name = "require_otp_for_email", nullable = false)
    private Boolean requireOtpForEmail = false;

    @Column(name = "require_otp_for_phone", nullable = false)
    private Boolean requireOtpForPhone = false;

    // --- Constructors ---

    public UserSecuritySetting() {}

    public UserSecuritySetting(User user) {
        this.user = user;
    }

    // --- Methods ---

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Boolean getRequireOtpForPassword() {
        return requireOtpForPassword;
    }

    public void setRequireOtpForPassword(Boolean requireOtpForPassword) {
        this.requireOtpForPassword = requireOtpForPassword;
    }

    public Boolean getRequireOtpForEmail() {
        return requireOtpForEmail;
    }

    public void setRequireOtpForEmail(Boolean requireOtpForEmail) {
        this.requireOtpForEmail = requireOtpForEmail;
    }

    public Boolean getRequireOtpForPhone() {
        return requireOtpForPhone;
    }

    public void setRequireOtpForPhone(Boolean requireOtpForPhone) {
        this.requireOtpForPhone = requireOtpForPhone;
    }
}
