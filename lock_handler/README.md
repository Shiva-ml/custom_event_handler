## Custom Event Handler

### Build the Application
- First, run the following command to build the `org.wso2.custom.event.handler`.
```bash
mvn clean install -DskipTests
```
- You will find the artifact `org.wso2.custom.event.handler-1.0-SNAPSHOT.jar` in the `/target` directory of the code base.

### Configure WSO2 IS
- After building the project, paste the artifact in `<IS_HOME>/repository/components/dropins` directory.
- Open `<IS_HOME>/repository/conf/deployment.toml` file and add the following configurations.
```toml
[[event_handler]]
name="custom.event.handler"
subscriptions=["POST_AUTHENTICATION"]
```
- The `name` should be the one you have mentioned by overriding the `getName()` method.
- Next, start the WSO2 IS, with the following command to open it in OSGi mode.
```bash
./wso2server.sh -DosgiConsole
```
- After starting, you can check whether the custom federated authenticator is in `ACTIVE` state or not.
```bash
ss org.wso2.custom.event.handler 
```

## Test the Custom Event Handler
- Now when you authenticate yourself to any application connected with IS, the `POST_AUTHENTICATION` event will run and you will find those logs in the terminal.