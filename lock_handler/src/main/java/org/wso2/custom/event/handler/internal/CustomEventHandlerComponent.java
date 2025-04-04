package org.wso2.custom.event.handler.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.handler.event.account.lock.AccountLockHandler;
import org.wso2.custom.event.handler.CustomAccountLockHandler;

@Component(name = "org.wso2.custom.event.handler",
        immediate = true)
public class CustomEventHandlerComponent {

    private static final Log log = LogFactory.getLog(CustomEventHandlerComponent.class);

    @Activate
    protected void activate(ComponentContext ctx){

        CustomAccountLockHandler eventHandler = new CustomAccountLockHandler();
        ctx.getBundleContext().registerService(AccountLockHandler.class.getName(), eventHandler, null);
        log.info("Custom event handler activated successfully.");
    }

    @Deactivate
    protected void deactivate(ComponentContext ctx){
        if(log.isDebugEnabled()){
            log.debug("Custom event handler is deactivated");
        }
    }
}