import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;

public class Main implements BurpExtension, HttpHandler {

    MontoyaApi api;
    Logging logging;
    String NAME = "JWT Update";
    String ONLOAD_MESSAGE = "Extension loaded!\nThis extension handles JWT update\n";
    String JWT_TOKEN_HEADER_VALUE = "";
    String AUTHORIZATION_HEADER = "Authorization";

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName(NAME);
        this.logging = api.logging();
        this.logging.logToOutput(ONLOAD_MESSAGE);

        api.http().registerHttpHandler(this);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        /*
         * Check request comes from a correct source and have the authorization header.
         * Then it should store the authorization header value to the JWT_TOKEN_HEADER_VALUE.
         * */
        if(httpRequestToBeSent.toolSource().isFromTool(ToolType.PROXY)){
            if(httpRequestToBeSent.isInScope() && httpRequestToBeSent.hasHeader(AUTHORIZATION_HEADER)){
                JWT_TOKEN_HEADER_VALUE = httpRequestToBeSent.headerValue(AUTHORIZATION_HEADER);
            }
        }
        /*
        * Direct update of the authorization header.
        * */
        if(!httpRequestToBeSent.toolSource().isFromTool(ToolType.PROXY)){
            HttpRequest updatedRequest = httpRequestToBeSent.withUpdatedHeader(AUTHORIZATION_HEADER, JWT_TOKEN_HEADER_VALUE);
            logging.logToOutput("Authorization header updated: " + JWT_TOKEN_HEADER_VALUE);
            return RequestToBeSentAction.continueWith(updatedRequest);
        }
        return null;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        /*
        * Do nothing to the Response.
        * */
        return null;
    }
}
