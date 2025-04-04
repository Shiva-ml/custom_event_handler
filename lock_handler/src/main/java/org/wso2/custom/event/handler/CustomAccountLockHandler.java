package org.wso2.custom.event.handler;


import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityMgtConstants;
import org.wso2.carbon.identity.handler.event.account.lock.AccountLockHandler;
import org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockException;
import org.wso2.carbon.identity.handler.event.account.lock.internal.AccountServiceDataHolder;
import org.wso2.carbon.identity.handler.event.account.lock.util.AccountUtil;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;


import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.*;
import static org.wso2.carbon.identity.governance.IdentityMgtConstants.LockedReason.MAX_ATTEMPTS_EXCEEDED;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.*;
import static org.wso2.carbon.user.core.UserCoreConstants.ErrorCode.INVALID_CREDENTIAL;
import static org.wso2.carbon.user.core.UserCoreConstants.ErrorCode.USER_IS_LOCKED;
import static org.wso2.custom.event.handler.internal.AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM;

/**
 * Implementation of account lock handler.
 */
public class CustomAccountLockHandler extends AccountLockHandler {

    public static final Log AUDIT_LOG = LogFactory.getLog("AUDIT_LOG");
    private static final Log log = LogFactory.getLog(CustomAccountLockHandler.class);
    private static final String FAILED_SMS_OTP_ATTEMPTS_CLAIM = "http://wso2.org/claims/identity/failedSmsOtpAttempts";;

    private static ThreadLocal<String> lockedState = new ThreadLocal<>();


    @Override
    public String getName() {
        return "CustomAccountLockHandler";
    }
    @Override
    public int getPriority(MessageContext messageContext){
        return 100;
    }


    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        // This property is added to disable the account lock handler completely to enhance the performance. This
        // can be done only where we are not using any account lock related features.
        log.info("handle event method");


        Map<String, Object> eventProperties = event.getEventProperties();
        UserStoreManager userStoreManager = (UserStoreManager) eventProperties.get(USER_STORE_MANAGER);

        // Basic data from event.
        String userName = (String) eventProperties.get(USER_NAME);
        String userStoreDomainName = AccountUtil.getUserStoreDomainName(userStoreManager);
        String tenantDomain = (String) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);

        // Check whether user exists.
        String usernameWithDomain = UserCoreUtil.addDomainToName(userName, userStoreDomainName);
        boolean userExists;
        try {
            userExists = userStoreManager.isExistingUser(usernameWithDomain);
        } catch (UserStoreException e) {
            throw new IdentityEventException("Error in accessing user store", e);
        }

        // If this user does not exist, no use of going forward.
        if (!userExists) {
            return;
        }

        // Force password related properties.
        String adminPasswordResetAccountLockNotificationProperty = IdentityUtil
                .getProperty(AccountConstants.ADMIN_FORCE_PASSWORD_RESET_ACCOUNT_LOCK_NOTIFICATION_ENABLE_PROPERTY);
        String adminPasswordResetAccountUnlockNotificationProperty = IdentityUtil
                .getProperty(AccountConstants.ADMIN_FORCE_PASSWORD_RESET_ACCOUNT_UNLOCK_NOTIFICATION_ENABLE_PROPERTY);
        boolean adminForcePasswordResetLockNotificationEnabled = Boolean
                .parseBoolean(adminPasswordResetAccountLockNotificationProperty);
        boolean adminForcePasswordResetUnlockNotificationEnabled = Boolean
                .parseBoolean(adminPasswordResetAccountUnlockNotificationProperty);

        // Read identity properties.
        Property[] identityProperties;
        try {
            identityProperties = AccountServiceDataHolder.getInstance().getIdentityGovernanceService()
                    .getConfiguration(getPropertyNames(), tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw new IdentityEventException("Error while retrieving Account Locking Handler properties.", e);
        }

        // We need to derive below values from identity properties.
        boolean accountLockOnFailedAttemptsEnabled = false;
        String accountLockTime = "0";
        int maximumFailedAttempts = 0;
        double unlockTimeRatio = 1;

        // Go through every property and get the values we need. These properties are from identity-event.properties
        // file.
        for (Property identityProperty : identityProperties) {
            switch (identityProperty.getName()) {
                case AccountConstants.ACCOUNT_LOCK_MAX_FAILED_ATTEMPTS_PROPERTY:
                    accountLockOnFailedAttemptsEnabled = Boolean.parseBoolean(identityProperty.getValue());
                    break;
                case AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY: {
                    String value = identityProperty.getValue();
                    if (NumberUtils.isNumber(value)) {
                        maximumFailedAttempts = Integer.parseInt(identityProperty.getValue());
                    }
                    break;
                }
                case AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY:
                    accountLockTime = identityProperty.getValue();
                    break;
                case AccountConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY: {
                    String value = identityProperty.getValue();
                    if (NumberUtils.isNumber(value)) {
                        if (Integer.parseInt(value) > 0) {
                            unlockTimeRatio = Integer.parseInt(value);
                        }
                    }
                    break;
                }
            }
        }

        // Based on the event name, we need to handle each case separately.
        switch (event.getEventName()) {
            case IdentityEventConstants.Event.PRE_AUTHENTICATION:
                handlePreAuthentication(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                        identityProperties, maximumFailedAttempts, accountLockTime, unlockTimeRatio);
                break;
            case IdentityEventConstants.Event.POST_AUTHENTICATION:
                handlePostAuthentication(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                        identityProperties, maximumFailedAttempts, accountLockTime, unlockTimeRatio,
                        accountLockOnFailedAttemptsEnabled);
                break;
            case IdentityEventConstants.Event.PRE_SET_USER_CLAIMS:
                handlePreSetUserClaimValues(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                        identityProperties, maximumFailedAttempts, accountLockTime, unlockTimeRatio);
                break;
            case IdentityEventConstants.Event.POST_SET_USER_CLAIMS:
                PrivilegedCarbonContext.startTenantFlow();
                try {
                    PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);
                    handlePostSetUserClaimValues(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                            identityProperties, maximumFailedAttempts, accountLockTime, unlockTimeRatio,
                            adminForcePasswordResetLockNotificationEnabled,
                            adminForcePasswordResetUnlockNotificationEnabled);
                } finally {
                    PrivilegedCarbonContext.endTenantFlow();
                }
                break;
            case IdentityEventConstants.Event.POST_NON_BASIC_AUTHENTICATION:
                // This will be invoked when an authenticator fires event POST_NON_BASIC_AUTHENTICATION.
                // This is similar to the POST_AUTHENTICATION.
                handleNonBasicAuthentication(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                        identityProperties, maximumFailedAttempts, accountLockTime, unlockTimeRatio,
                        accountLockOnFailedAttemptsEnabled);
                break;
        }
    }

    @Override
    protected boolean handlePostAuthentication(Event event, String userName, UserStoreManager userStoreManager,
                                               String userStoreDomainName, String tenantDomain,
                                               Property[] identityProperties, int maximumFailedAttempts,
                                               String accountLockTime, double unlockTimeRatio,
                                               boolean accountLockOnFailedAttemptsEnabled) throws AccountLockException {

        log.info("handle post authentication");
        Map<String, String> claimValues = null;

        // Resolve the claim which stores failed attempts depending on the authenticator.
        Map<String, Object> eventProperties = event.getEventProperties();
        String authenticator = String.valueOf(eventProperties.get(AUTHENTICATOR_NAME));
        String failedAttemptsClaim = resolveFailedLoginAttemptsCounterClaim(authenticator, eventProperties);



        try {
            claimValues = userStoreManager.getUserClaimValues(userName,
                    new String[]{ACCOUNT_UNLOCK_TIME_CLAIM,
                            AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM,
                            FAILED_LOGIN_ATTEMPTS_CLAIM, ACCOUNT_LOCKED_CLAIM,
                            AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI, failedAttemptsClaim},
                    UserCoreConstants.DEFAULT_PROFILE);

        } catch (UserStoreException e) {
            throw new AccountLockException(String.format("Error occurred while retrieving %s , %s , %s , %s, %s " +
                            "and %s claim values for user domain.", ACCOUNT_UNLOCK_TIME_CLAIM,
                    AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, FAILED_LOGIN_ATTEMPTS_CLAIM,
                    ACCOUNT_LOCKED_CLAIM, AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI,
                    failedAttemptsClaim, userStoreDomainName), e);
        }

        long unlockTime = getUnlockTime(claimValues.get(ACCOUNT_UNLOCK_TIME_CLAIM));

        if (!AccountUtil.isPreAuthLockedAccountCheckEnabled() &&
                handleLockedAccount(userName, userStoreManager, userStoreDomainName, tenantDomain, claimValues)) {
            /*
             * handleLockedAccount will return true if the account locking is bypassed for this user
             * in which case we don't need to proceed.
             */
            return true;
        }

        if (!accountLockOnFailedAttemptsEnabled) {
            if (log.isDebugEnabled()) {
                log.debug("Account lock on failed login attempts is disabled in tenant: " + tenantDomain);
            }
            return true;
        }

        int currentFailedAttempts = 0;
        int currentFailedLoginLockouts = 0;

        // Get the account locking related claims from the user store.
        String currentFailedAttemptCount = claimValues.get(failedAttemptsClaim);
        if (StringUtils.isNotBlank(currentFailedAttemptCount)) {
            currentFailedAttempts = Integer.parseInt(currentFailedAttemptCount);
        }
        String currentFailedLoginLockoutCount = claimValues.get(FAILED_LOGIN_LOCKOUT_COUNT_CLAIM);
        if (StringUtils.isNotBlank(currentFailedLoginLockoutCount)) {
            currentFailedLoginLockouts = Integer.parseInt(currentFailedLoginLockoutCount);
        }

        Map<String, String> newClaims = new HashMap<>();
        if ((Boolean) event.getEventProperties().get(IdentityEventConstants.EventProperty.OPERATION_STATUS)) {

            // User is authenticated, Need to check the unlock-time to verify whether the user is previously locked.
            String accountLockClaim = claimValues.get(ACCOUNT_LOCKED_CLAIM);

            // Return if user authentication is successful on the first try.
            if (!Boolean.parseBoolean(accountLockClaim) && currentFailedAttempts == 0 &&
                    currentFailedLoginLockouts == 0 && unlockTime == 0) {
                return true;
            }

            newClaims.put(AccountConstants.FAILED_LOGIN_ATTEMPTS_BEFORE_SUCCESS_CLAIM,
                    String.valueOf(currentFailedAttempts + (currentFailedLoginLockouts * maximumFailedAttempts)));
            if (isUserUnlockable(userName, userStoreManager, currentFailedAttempts, unlockTime, accountLockClaim)) {
                newClaims.put(failedAttemptsClaim, "0");
                newClaims.put(ACCOUNT_UNLOCK_TIME_CLAIM, "0");
                newClaims.put(ACCOUNT_LOCKED_CLAIM, Boolean.FALSE.toString());
                boolean isAuthenticationFrameworkFlow = false;
                if (IdentityUtil.threadLocalProperties.get().get(
                        FrameworkConstants.AUTHENTICATION_FRAMEWORK_FLOW) != null) {
                    isAuthenticationFrameworkFlow = (boolean) IdentityUtil.threadLocalProperties.get().get(
                            FrameworkConstants.AUTHENTICATION_FRAMEWORK_FLOW);
                }
                if (!isAuthenticationFrameworkFlow) {
                    newClaims.put(FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, "0");
                }
                IdentityUtil.threadLocalProperties.get().put(AccountConstants.ADMIN_INITIATED, false);
            }
            setUserClaims(userName, tenantDomain, userStoreManager, newClaims);
        } else {
            // User authentication failed.
            // Skip account lock if account lock by pass is enabled for the userstore manager.
            if (AccountUtil.isAccountLockBypassForUserStore(userStoreManager)) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Account lock has been by passed for the %s userstore manager.",
                            userStoreManager.getRealmConfiguration().getRealmClassName()));
                }
                return true;
            }
            currentFailedAttempts += 1;
            newClaims.put(failedAttemptsClaim, Integer.toString(currentFailedAttempts));
            newClaims.put(AccountConstants.FAILED_LOGIN_ATTEMPTS_BEFORE_SUCCESS_CLAIM, "0");
            long accountLockDuration = 0;
            boolean isMaxAttemptsExceeded = false;

            if (AccountUtil.isAccountLockByPassForUser(userStoreManager, userName)) {
                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(INVALID_CREDENTIAL,
                        currentFailedAttempts, maximumFailedAttempts);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                if (log.isDebugEnabled()) {
                    log.debug("Login attempt failed. Bypassing account locking for user: " + userName);
                }
                return true;
            } else if (currentFailedAttempts >= maximumFailedAttempts) {
                // Current failed attempts exceeded maximum allowed attempts. So user should be locked.
                isMaxAttemptsExceeded = true;
                newClaims.put(ACCOUNT_LOCKED_CLAIM, "true");
                newClaims.put(AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI, MAX_ATTEMPTS_EXCEEDED.toString());
                if (NumberUtils.isNumber(accountLockTime)) {
                    long unlockTimePropertyValue = Integer.parseInt(accountLockTime);
                    if (unlockTimePropertyValue != 0) {
                        if (log.isDebugEnabled()) {
                            String msg = String.format("Set account unlock time for user: %s in user store: %s " +
                                            "in tenant: %s. Adding account unlock time out: %s, account lock timeout " +
                                            "increment factor: %s raised to the power of failed login attempt cycles: %s",
                                    userName, userStoreManager, tenantDomain, unlockTimePropertyValue,
                                    unlockTimeRatio, currentFailedLoginLockouts);
                            log.debug(msg);
                        }
                        /*
                         * If account unlock time out is configured, calculates the account unlock time as below.
                         * account unlock time =
                         *      current system time + (account unlock time out configured + account lock time out
                         *      increment factor raised to the power of failed login attempt cycles)
                         */
                        unlockTimePropertyValue = (long) (unlockTimePropertyValue * 1000 * 60 * Math.pow
                                (unlockTimeRatio, currentFailedLoginLockouts));
                        accountLockDuration = unlockTimePropertyValue / 60000;
                        unlockTime = System.currentTimeMillis() + unlockTimePropertyValue;
                        if (failedAttemptsClaim.equals(FAILED_SMS_OTP_ATTEMPTS_CLAIM)){
                            newClaims.put(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM, Long.toString(unlockTime));
                        } else {
                            newClaims.put(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM, "0");

                        }
                    }
                }
                currentFailedLoginLockouts += 1;

                if (currentFailedLoginLockouts > 1) {
                    boolean notificationOnLockIncrement = getNotificationOnLockIncrementConfig(tenantDomain);
                    // If the 'NOTIFY_ON_LOCK_DURATION_INCREMENT' config is enabled, trigger the account lock email
                    // notification with the new lock duration information.
                    if (notificationOnLockIncrement) {
                        Property identityProperty = new Property();
                        identityProperty.setName(AccountConstants.ACCOUNT_UNLOCK_TIME);
                        identityProperty.setValue(Long.toString(accountLockDuration));
                        triggerNotificationOnAccountLockIncrement(userName, userStoreDomainName,
                                claimValues.get(AccountConstants.ACCOUNT_STATE_CLAIM_URI), tenantDomain,
                                new Property[]{identityProperty});
                    }
                }

                newClaims.put(FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, Integer.toString(currentFailedLoginLockouts));
                newClaims.put(failedAttemptsClaim, "0");

                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                        USER_IS_LOCKED + ":" + AccountConstants.MAX_ATTEMPTS_EXCEEDED, currentFailedAttempts,
                        maximumFailedAttempts);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                IdentityUtil.threadLocalProperties.get().put(IdentityCoreConstants.USER_ACCOUNT_STATE, USER_IS_LOCKED);
                if (log.isDebugEnabled()) {
                    log.debug(String.format("User: %s is locked due to exceeded the maximum allowed failed " +
                            "attempts", userName));
                }
                IdentityUtil.threadLocalProperties.get().put(AccountConstants.ADMIN_INITIATED, false);
            } else {
                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(INVALID_CREDENTIAL,
                        currentFailedAttempts, maximumFailedAttempts);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
            }
            try {
                setUserClaims(userName, tenantDomain, userStoreManager, newClaims);
            } catch (NumberFormatException e) {
                throw new AccountLockException("Error occurred while parsing config values", e);
            }
            if (isMaxAttemptsExceeded) {
                /*
                 * Setting the error message context with locked reason again here, as it is overridden when setting
                 * user claims by org.wso2.carbon.identity.governance.listener.IdentityStoreEventListener .
                 */
                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                        USER_IS_LOCKED + ":" + AccountConstants.MAX_ATTEMPTS_EXCEEDED, currentFailedAttempts,
                        maximumFailedAttempts);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
            }
        }
        return true;

    }




    private String resolveFailedLoginAttemptsCounterClaim(String authenticator, Map<String, Object> eventProperties) {

        if (StringUtils.isBlank(authenticator)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No authenticator has specified. Therefore, using the default claim: %s as " +
                        "failed attempt counting claim: %s", authenticator, FAILED_LOGIN_ATTEMPTS_CLAIM));
            }
        }
        if (eventProperties.get(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM) == null ||
                StringUtils.isBlank(String.valueOf(eventProperties.get(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM)))) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No failed attempt count claim defined for authenticator: %s. Therefore, " +
                                "using the default claim: %s as failed attempt counting claim",
                        authenticator, FAILED_LOGIN_ATTEMPTS_CLAIM));
            }
            return FAILED_LOGIN_ATTEMPTS_CLAIM;
        }
        return String.valueOf(eventProperties.get(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM));
    }


    private boolean handleLockedAccount(String userName, UserStoreManager userStoreManager, String userStoreDomainName,
                                        String tenantDomain, Map<String, String> claimValues)
            throws AccountLockException {

        long unlockTime = getUnlockTime(claimValues.get(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM));

        if (isAccountLock(claimValues.get(AccountConstants.ACCOUNT_LOCKED_CLAIM))) {
            if (AccountUtil.isAccountLockByPassForUser(userStoreManager, userName)) {
                if (log.isDebugEnabled()) {
                    String bypassMsg = String.format("Account locking is bypassed as lock bypass role: %s is " +
                            "assigned to the user %s", AccountConstants.ACCOUNT_LOCK_BYPASS_ROLE, userName);
                    log.debug(bypassMsg);
                }
                return true;
            }
            /*
             * User account is locked. If the current time is not exceeded user unlock time, send an error message
             * saying user is locked, otherwise users can try to authenticate and unlock their account upon a
             * successful authentication.
             */
            if (System.currentTimeMillis() < unlockTime || unlockTime == 0) {
                String accountLockedReason = claimValues.get(AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI);
                boolean isAdminInitiatedAccountLock = ADMIN_INITIATED.toString().equals(accountLockedReason);

                String message;
                if (StringUtils.isNotBlank(userStoreDomainName)) {
                    message = String.format("Account is locked for user: %s in user store: %s in tenant: %s. " +
                                    "Cannot login until the account is unlocked.", AccountUtil.maskIfRequired(userName),
                            userStoreDomainName, tenantDomain);
                    if (isAdminInitiatedAccountLock) {
                        message = String.format("Account is locked by admin for user: %s in user store: %s in " +
                                        "tenant: %s. Cannot login until the account is unlocked.",
                                AccountUtil.maskIfRequired(userName), userStoreDomainName, tenantDomain);
                    }
                } else {
                    message = String.format("Account is locked for user: %s in tenant: %s. Cannot login until the " +
                            "account is unlocked.", AccountUtil.maskIfRequired(userName), tenantDomain);
                    if (isAdminInitiatedAccountLock) {
                        message = String.format("Account is locked by admin for user: %s in tenant: %s. " +
                                        "Cannot login until the account is unlocked.", AccountUtil.maskIfRequired(
                                        userName),
                                tenantDomain);
                    }
                }
                if (log.isDebugEnabled()) {
                    log.debug(message);
                }

                if (isAdminInitiatedAccountLock) {
                    IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                            USER_IS_LOCKED + ":" + AccountConstants.ADMIN_INITIATED);
                    IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                    throw new AccountLockException(USER_IS_LOCKED + ":" + AccountConstants.ADMIN_INITIATED, message);
                }

                if (MAX_ATTEMPTS_EXCEEDED.toString().equals(accountLockedReason)) {
                    IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                            USER_IS_LOCKED + ":" + AccountConstants.MAX_ATTEMPTS_EXCEEDED);
                    IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                    throw new AccountLockException(USER_IS_LOCKED, message);
                }

                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(USER_IS_LOCKED);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                throw new AccountLockException(USER_IS_LOCKED, message);
            }
        }
        return false;
    }



    private boolean isUserUnlockable(String userName, UserStoreManager userStoreManager, int currentFailedAttempts,
                                     long unlockTime, String accountLockClaim) throws AccountLockException {

        return (unlockTime != 0 && System.currentTimeMillis() >= unlockTime)
                || currentFailedAttempts > 0
                || ((Boolean.parseBoolean(accountLockClaim)
                && AccountUtil.isAccountLockByPassForUser(userStoreManager, userName)));
    }

    private void setUserClaims(String username, String tenantDomain, UserStoreManager userStoreManager,
                               Map<String, String> claimsList) throws AccountLockException {

        try {
            userStoreManager.setUserClaimValues(username, claimsList, UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            throw new AccountLockException(String.format("Error occurred while updating the user claims " +
                    "for user: %s in tenant: %s", AccountUtil.maskIfRequired(username), tenantDomain), e);
        }
    }

    private boolean getNotificationOnLockIncrementConfig(String tenantDomain) {

        boolean notificationOnLockIncrement = false;
        try {
            notificationOnLockIncrement = Boolean.parseBoolean(AccountUtil.getConnectorConfig(AccountConstants
                    .NOTIFY_ON_LOCK_DURATION_INCREMENT, tenantDomain));
        } catch (IdentityEventException e) {
            log.warn("Error while reading notification on lock increment property in account lock handler. "
                    + e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("Error while reading notification on lock increment property in account lock " +
                        "handler", e);
            }
        }
        return notificationOnLockIncrement;
    }


    private void triggerNotificationOnAccountLockIncrement(String userName, String userStoreDomainName,
                                                           String userAccountStateClaimValue, String tenantDomain,
                                                           Property[] identityProperties) throws AccountLockException {

        boolean notificationInternallyManage = true;
        try {
            notificationInternallyManage = Boolean.parseBoolean(AccountUtil.getConnectorConfig(AccountConstants
                    .NOTIFICATION_INTERNALLY_MANAGE, tenantDomain));
        } catch (IdentityEventException e) {
            log.warn("Error while reading Notification internally manage property in account lock handler." +
                    e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("Error while reading Notification internally manage property in account lock handler", e);
            }
        }

        if (notificationInternallyManage && AccountUtil.isTemplateExists
                (AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED_FAILED_ATTEMPT, tenantDomain)) {
            String existingAccountStateClaimValue = getAccountState(userAccountStateClaimValue, tenantDomain);

            // Send locked email only if the accountState claim value doesn't have PENDING_AFUPR, PENDING_SR,
            // PENDING_EV or PENDING_LR.
            if (!IdentityMgtConstants.AccountStates.PENDING_ADMIN_FORCED_USER_PASSWORD_RESET.equals(
                    existingAccountStateClaimValue) &&
                    !AccountConstants.PENDING_SELF_REGISTRATION.equals(existingAccountStateClaimValue) &&
                    !AccountConstants.PENDING_EMAIL_VERIFICATION.equals(existingAccountStateClaimValue) &&
                    !AccountConstants.PENDING_LITE_REGISTRATION.equals(existingAccountStateClaimValue)) {
                triggerNotification(userName, userStoreDomainName, tenantDomain, identityProperties,
                        AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED_FAILED_ATTEMPT);
            }
        }
    }



    private String getAccountState(String accountStateClaimValue, String tenantDomain) throws AccountLockException {

        boolean isAccountStateClaimExist = AccountUtil.isAccountStateClaimExisting(tenantDomain);
        if (!isAccountStateClaimExist) {
            accountStateClaimValue = "";
        }
        return accountStateClaimValue;
    }




}