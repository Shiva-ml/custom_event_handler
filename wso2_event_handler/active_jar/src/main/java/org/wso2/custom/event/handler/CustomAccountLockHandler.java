package org.wso2.custom.event.handler;


import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.MDC;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityMgtConstants;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.handler.event.account.lock.AccountLockHandler;
import org.wso2.carbon.identity.handler.event.account.lock.AuditConstants;
import org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockException;
import org.wso2.carbon.identity.handler.event.account.lock.internal.AccountServiceDataHolder;
import org.wso2.carbon.identity.handler.event.account.lock.util.AccountUtil;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.*;
import static org.wso2.carbon.identity.governance.IdentityMgtConstants.LockedReason.MAX_ATTEMPTS_EXCEEDED;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.ACCOUNT_LOCKED_CLAIM;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM;
import static org.wso2.carbon.user.core.UserCoreConstants.ErrorCode.INVALID_CREDENTIAL;
import static org.wso2.carbon.user.core.UserCoreConstants.ErrorCode.USER_IS_LOCKED;
import static org.wso2.custom.event.handler.internal.AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM;

/**
 * Implementation of account lock handler.
 */
public class CustomAccountLockHandler extends AccountLockHandler {

    public static final Log AUDIT_LOG = LogFactory.getLog("AUDIT_LOG");
    private static final Log log = LogFactory.getLog(CustomAccountLockHandler.class);

    private static ThreadLocal<String> lockedState = new ThreadLocal<>();

    private enum lockedStates {LOCKED_MODIFIED, UNLOCKED_MODIFIED, LOCKED_UNMODIFIED, UNLOCKED_UNMODIFIED}


    @Override
    public String getName() {
        return "CustomAccountLockHandler";
    }

    @Override
    protected boolean handlePostAuthentication(Event event, String userName, UserStoreManager userStoreManager,
                                               String userStoreDomainName, String tenantDomain,
                                               Property[] identityProperties, int maximumFailedAttempts,
                                               String accountLockTime, double unlockTimeRatio,
                                               boolean accountLockOnFailedAttemptsEnabled) throws AccountLockException {

        Map<String, String> claimValues = null;

        // Resolve the claim which stores failed attempts depending on the authenticator.
        Map<String, Object> eventProperties = event.getEventProperties();
        String authenticator = String.valueOf(eventProperties.get(AUTHENTICATOR_NAME));
        String failedAttemptsClaim = resolveFailedLoginAttemptsCounterClaim(authenticator, eventProperties);

        boolean result = super.handlePostAuthentication(event, userName, userStoreManager,
                userStoreDomainName, tenantDomain, identityProperties, maximumFailedAttempts,
                accountLockTime, unlockTimeRatio, accountLockOnFailedAttemptsEnabled);


        try {
            claimValues = userStoreManager.getUserClaimValues(userName,
                    new String[]{ACCOUNT_UNLOCK_TIME_CLAIM,
                            AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM,
                            AccountConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, ACCOUNT_LOCKED_CLAIM,
                            AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI, failedAttemptsClaim},
                    UserCoreConstants.DEFAULT_PROFILE);

        } catch (UserStoreException e) {
            throw new AccountLockException(String.format("Error occurred while retrieving %s , %s , %s , %s, %s " +
                            "and %s claim values for user domain.", ACCOUNT_UNLOCK_TIME_CLAIM,
                    AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, AccountConstants.FAILED_LOGIN_ATTEMPTS_CLAIM,
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
                        newClaims.put(ACCOUNT_UNLOCK_TIME_CLAIM, Long.toString(unlockTime));
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

}