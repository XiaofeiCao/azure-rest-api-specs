import "@azure-tools/typespec-azure-core";
import "@azure-tools/typespec-azure-resource-manager";
import "@typespec/openapi";
import "@typespec/rest";
import "./models.tsp";
import "./WebPubSubResource.tsp";

using TypeSpec.Rest;
using Azure.ResourceManager;
using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace Microsoft.SignalRService;
/**
 * A private endpoint connection to an azure resource
 */
@parentResource(WebPubSubResource)
model PrivateEndpointConnection
  is Azure.ResourceManager.ProxyResource<PrivateEndpointConnectionProperties> {
  ...ResourceNameParameter<
    Resource = PrivateEndpointConnection,
    KeyName = "privateEndpointConnectionName",
    SegmentName = "privateEndpointConnections",
    NamePattern = ""
  >;
}


/**
 * A class that describes the properties of the resource
 */
model WebPubSubProperties {
  /**
   * Provisioning state of the resource.
   */
  @visibility(Lifecycle.Read)
  provisioningState?: ProvisioningState;

  /**
   * The publicly accessible IP of the resource.
   */
  #suppress "@azure-tools/typespec-azure-core/casing-style" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  @visibility(Lifecycle.Read)
  externalIP?: string;

  /**
   * FQDN of the service instance.
   */
  @visibility(Lifecycle.Read)
  hostName?: string;

  /**
   * The publicly accessible port of the resource which is designed for browser/client side usage.
   */
  @visibility(Lifecycle.Read)
  publicPort?: int32;

  /**
   * The publicly accessible port of the resource which is designed for customer server side usage.
   */
  @visibility(Lifecycle.Read)
  serverPort?: int32;

  /**
   * Version of the resource. Probably you need the same or higher version of client SDKs.
   */
  @visibility(Lifecycle.Read)
  version?: string;

  /**
   * Private endpoint connections to the resource.
   */
  @visibility(Lifecycle.Read)
  @OpenAPI.extension("x-ms-identifiers", #[])
  privateEndpointConnections?: PrivateEndpointConnection[];

  /**
   * The list of shared private link resources.
   */
  @visibility(Lifecycle.Read)
  @OpenAPI.extension("x-ms-identifiers", #[])
  sharedPrivateLinkResources?: SharedPrivateLinkResource[];

  /**
   * TLS settings for the resource
   */
  tls?: WebPubSubTlsSettings;

  /**
   * Deprecated.
   */
  @visibility(Lifecycle.Read)
  hostNamePrefix?: string;

  /**
   * Live trace configuration of a Microsoft.SignalRService resource.
   */
  liveTraceConfiguration?: LiveTraceConfiguration;

  /**
   * Resource log configuration of a Microsoft.SignalRService resource.
   */
  resourceLogConfiguration?: ResourceLogConfiguration;

  /**
   * Network ACLs for the resource
   */
  #suppress "@azure-tools/typespec-azure-core/casing-style" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  networkACLs?: WebPubSubNetworkACLs;

  /**
   * Application firewall settings for the resource
   */
  applicationFirewall?: ApplicationFirewallSettings;

  /**
   * Enable or disable public network access. Default to "Enabled".
   * When it's Enabled, network ACLs still apply.
   * When it's Disabled, public network access is always disabled no matter what you set in network ACLs.
   */
  publicNetworkAccess?: string = "Enabled";

  /**
   * DisableLocalAuth
   * Enable or disable local auth with AccessKey
   * When set as true, connection with AccessKey=xxx won't work.
   */
  disableLocalAuth?: boolean = false;

  /**
   * DisableLocalAuth
   * Enable or disable aad auth
   * When set as true, connection with AuthType=aad won't work.
   */
  disableAadAuth?: boolean = false;

  /**
   * Enable or disable the regional endpoint. Default to "Enabled".
   * When it's Disabled, new connections will not be routed to this endpoint, however existing connections will not be affected.
   * This property is replica specific. Disable the regional endpoint without replica is not allowed.
   */
  regionEndpointEnabled?: string = "Enabled";

  /**
   * Stop or start the resource.  Default to "False".
   * When it's true, the data plane of the resource is shutdown.
   * When it's false, the data plane of the resource is started.
   */
  resourceStopped?: string = "false";

  /**
   * SocketIO settings for the resource
   */
  #suppress "@azure-tools/typespec-azure-core/casing-style" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  socketIO?: WebPubSubSocketIOSettings;
}

@armResourceOperations
interface PrivateEndpointConnections {
  /**
   * Get the specified private endpoint connection
   */
  get is ArmResourceRead<PrivateEndpointConnection>;

  /**
   * Update the state of specified private endpoint connection
   */
  #suppress "@azure-tools/typespec-azure-resource-manager/arm-put-operation-response-codes" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  update is ArmResourceCreateOrReplaceSync<
    PrivateEndpointConnection,
    Response = ArmResourceUpdatedResponse<PrivateEndpointConnection>
  >;

  /**
   * Delete the specified private endpoint connection
   */
  #suppress "@azure-tools/typespec-azure-resource-manager/arm-delete-operation-response-codes" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  delete is ArmResourceDeleteWithoutOkAsync<
    PrivateEndpointConnection,
    Response =
      | OkResponse
      | ArmDeletedResponse
      | ArmDeleteAcceptedLroResponse
      | ArmDeletedNoContentResponse
  >;

  /**
   * List private endpoint connections
   */
  list is ArmResourceListByParent<
    PrivateEndpointConnection,
    Response = ArmResponse<PrivateEndpointConnectionList>
  >;
}

@@doc(PrivateEndpointConnection.name,
  "The name of the private endpoint connection associated with the Azure resource."
);
@@doc(PrivateEndpointConnection.properties,
  "Private endpoint connection properties"
);
@@doc(PrivateEndpointConnections.update::parameters.resource,
  "The resource of private endpoint and its properties"
);
