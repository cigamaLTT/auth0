package com.cigama.auth0.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "user_devices")
public class UserDevice extends BaseAuditEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private String deviceId;

    private String deviceSignature; // Hash of browser/hardware fingerprints

    private String ipAddress;

    private String userAgent;

    private LocalDateTime lastLoginAt;

    private boolean isTrusted;

    public UserDevice() {}

    public UserDevice(String id, User user, String deviceId, String deviceSignature, String ipAddress, String userAgent, LocalDateTime lastLoginAt, boolean isTrusted) {
        this.id = id;
        this.user = user;
        this.deviceId = deviceId;
        this.deviceSignature = deviceSignature;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.lastLoginAt = lastLoginAt;
        this.isTrusted = isTrusted;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    public String getDeviceSignature() {
        return deviceSignature;
    }

    public void setDeviceSignature(String deviceSignature) {
        this.deviceSignature = deviceSignature;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public LocalDateTime getLastLoginAt() {
        return lastLoginAt;
    }

    public void setLastLoginAt(LocalDateTime lastLoginAt) {
        this.lastLoginAt = lastLoginAt;
    }

    public boolean isTrusted() {
        return isTrusted;
    }

    public void setTrusted(boolean trusted) {
        isTrusted = trusted;
    }

    public static UserDeviceBuilder builder() {
        return new UserDeviceBuilder();
    }

    public static class UserDeviceBuilder {
        private String id;
        private User user;
        private String deviceId;
        private String deviceSignature;
        private String ipAddress;
        private String userAgent;
        private LocalDateTime lastLoginAt;
        private boolean isTrusted;

        public UserDeviceBuilder id(String id) {
            this.id = id;
            return this;
        }

        public UserDeviceBuilder user(User user) {
            this.user = user;
            return this;
        }

        public UserDeviceBuilder deviceId(String deviceId) {
            this.deviceId = deviceId;
            return this;
        }

        public UserDeviceBuilder deviceSignature(String deviceSignature) {
            this.deviceSignature = deviceSignature;
            return this;
        }

        public UserDeviceBuilder ipAddress(String ipAddress) {
            this.ipAddress = ipAddress;
            return this;
        }

        public UserDeviceBuilder userAgent(String userAgent) {
            this.userAgent = userAgent;
            return this;
        }

        public UserDeviceBuilder lastLoginAt(LocalDateTime lastLoginAt) {
            this.lastLoginAt = lastLoginAt;
            return this;
        }

        public UserDeviceBuilder isTrusted(boolean isTrusted) {
            this.isTrusted = isTrusted;
            return this;
        }

        public UserDevice build() {
            return new UserDevice(id, user, deviceId, deviceSignature, ipAddress, userAgent, lastLoginAt, isTrusted);
        }
    }
}
