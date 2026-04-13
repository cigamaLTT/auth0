/**
 * DTO carrying only the data that is safe to serialize into a JWT payload.
 * Acts as the contract between the authentication service and the token infrastructure.
 * Fields must remain a flat, JSON-serializable structure for reliable ObjectMapper conversion.
 */
package com.cigama.auth0.dto;


public class JwtPayload {

    // --- Fields ---

    private String userId;
    private String username;
    private String firstName;
    private String lastName;
    private String role;
    private String clientId;
    private String deviceId;

    public JwtPayload() {}

    public JwtPayload(String userId, String username, String firstName, String lastName, String role, String clientId, String deviceId) {
        this.userId = userId;
        this.username = username;
        this.firstName = firstName;
        this.lastName = lastName;
        this.role = role;
        this.clientId = clientId;
        this.deviceId = deviceId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    public static JwtPayloadBuilder builder() {
        return new JwtPayloadBuilder();
    }

    public static class JwtPayloadBuilder {
        private String userId;
        private String username;
        private String firstName;
        private String lastName;
        private String role;
        private String clientId;
        private String deviceId;

        public JwtPayloadBuilder userId(String userId) {
            this.userId = userId;
            return this;
        }

        public JwtPayloadBuilder username(String username) {
            this.username = username;
            return this;
        }

        public JwtPayloadBuilder firstName(String firstName) {
            this.firstName = firstName;
            return this;
        }

        public JwtPayloadBuilder lastName(String lastName) {
            this.lastName = lastName;
            return this;
        }

        public JwtPayloadBuilder role(String role) {
            this.role = role;
            return this;
        }

        public JwtPayloadBuilder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public JwtPayloadBuilder deviceId(String deviceId) {
            this.deviceId = deviceId;
            return this;
        }

        public JwtPayload build() {
            return new JwtPayload(userId, username, firstName, lastName, role, clientId, deviceId);
        }
    }
}
